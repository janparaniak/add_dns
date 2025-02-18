import json
import os
import re
import textwrap
import ipaddress
import boto3
import time
import botocore.exceptions

import zendesk_connection
import openai_ops
import sc_approval_scenario

# ------------------------------------------------------------------------------
# CONFIGURATION & GLOBALS
# ------------------------------------------------------------------------------
TAG_NAME = "add_dns"

START_TAG = f"{TAG_NAME}-trigger"
WIP_TAG = f"{TAG_NAME}-trigger-processing"
COMPLETED_TAG = f"{TAG_NAME}-trigger-processed"
ATLAS_CUSTOM_CLOSURE_TAG = f"atlas-ticket-custom-closure"
PARAMETER_NAME = f"{TAG_NAME}_parameters"
PARAMETERS = None

# If DNS_ACCOUNT_ROLE_MAPPINGS is set, it should be a JSON array of account/role mappings.
# Otherwise, fallback to CENTRAL_ADMIN_ACCOUNT_ID / CENTRAL_ADMIN_ROLE_NAME.
DNS_ACCOUNT_ROLE_MAPPINGS = os.getenv("DNS_ACCOUNT_ROLE_MAPPINGS", None)

# ------------------------------------------------------------------------------
# HELPER FUNCTION FOR SENDING EMAIL NOTIFICATIONS VIA SES
# ------------------------------------------------------------------------------
def send_notification_email(subject, message):
    """
    Sends an email notification using SES if SEND_EMAIL_NOTIFICATIONS is enabled.
    Environment Variables:
      - SEND_EMAIL_NOTIFICATIONS: "true" or "1" to enable (case-insensitive).
      - NOTIFICATION_EMAIL: Recipient email address.
      - SES_SOURCE_EMAIL: Verified source email address.
      - AWS_REGION: (Optional) The SES region (defaults to us-east-1).
    """
    notify = os.getenv("SEND_EMAIL_NOTIFICATIONS", "false").lower() in ["true", "1"]
    if not notify:
        return

    recipient = os.getenv("NOTIFICATION_EMAIL", "jan.paraniak@trilogy.com")
    source = os.getenv("SES_SOURCE_EMAIL", recipient)
    ses_region = os.getenv("AWS_REGION", "us-east-1")

    ses = boto3.client("ses", region_name=ses_region)
    try:
        ses.send_email(
            Source=source,
            Destination={"ToAddresses": [recipient]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": message}}
            }
        )
        print(f"Notification email sent to {recipient}.")
    except Exception as e:
        print(f"Failed to send notification email: {e}")


# ------------------------------------------------------------------------------
# HELPER FUNCTION FOR RETRYING API CALLS (to avoid throttling errors)
# ------------------------------------------------------------------------------
def call_api(func, *args, **kwargs):
    max_retries = 5
    delay = 1
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error'].get('Code', '')
            if error_code in ['Throttling', 'RateExceeded', 'PriorRequestNotComplete']:
                print(f"Throttling error encountered: {e}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2
            else:
                raise
    return func(*args, **kwargs)


# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def reorder_mappings(mappings):
    """
    Reorder account mappings so that:
      - 646253092271 (Central Admin) is first,
      - 727712672144 (Contently Prod) is second,
      - then everything else in the existing order.
    """
    preferred = []
    others = []
    for mapping in mappings:
        acct = mapping.get("account_id")
        if acct == "646253092271" or acct == "727712672144":
            preferred.append(mapping)
        else:
            others.append(mapping)
    # Sort so that 646253092271 is index 0, 727712672144 is index 1
    preferred.sort(key=lambda m: 0 if m.get("account_id") == "646253092271" else 1)
    return preferred + others


def get_route53_client(account_id=None, role_name=None):
    if not account_id or not role_name:
        account_id = os.getenv('CENTRAL_ADMIN_ACCOUNT_ID')
        role_name = os.getenv('CENTRAL_ADMIN_ROLE_NAME')
        if not account_id or not role_name:
            print("CENTRAL_ADMIN_ACCOUNT_ID or CENTRAL_ADMIN_ROLE_NAME not set. Using local credentials.")
            return boto3.client('route53')

    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='LambdaDNSManagerSession'
        )
        creds = assumed_role['Credentials']
        return boto3.client(
            'route53',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
    except Exception as e:
        print(f"Error assuming role {role_arn}: {e}. Falling back to local route53 client.")
        return boto3.client('route53')


# ------------------------------------------------------------------------------
# DNS EXTRACTION / VALIDATION
# ------------------------------------------------------------------------------
def extract_dns_details(description):
    dns_details = {}
    patterns = {
        'dns_name': r"DNS Name:\s*(.+)",
        'domain': r"Domain:\s*(.+)",
        'dns_type': r"DNS Type:\s*(.+)",
        'dns_value': r"DNS Value:\s*(.+)"
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            dns_details[key] = match.group(1).strip()

    if dns_details.get('dns_name') == '@':
        dns_details['dns_name'] = ''
    return dns_details


def is_valid_hostname(hostname):
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    allowed = re.compile(r"^(?!-)[A-Z\d_-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def prevent_cname_at_apex(dns_details):
    dns_type = dns_details.get('dns_type', '').upper()
    dns_name = dns_details.get('dns_name', '').strip()
    if dns_type == 'CNAME' and not dns_name:
        return False, "Cannot add a CNAME record at the apex (root domain)."
    return True, ""


def validate_dns_details(dns_details):
    errors = []
    domain = dns_details.get('domain', '')
    try:
        domain = domain.encode('idna').decode('ascii')
    except UnicodeError:
        errors.append(f"Invalid internationalized domain name (IDN): {domain}")

    if not domain or not is_valid_hostname(domain):
        errors.append(f"Invalid domain format: {domain}")

    dns_name = dns_details.get('dns_name', '')
    if dns_name:
        try:
            dns_name = dns_name.encode('idna').decode('ascii')
        except UnicodeError:
            errors.append(f"Invalid internationalized DNS name (IDN): {dns_name}")
        if not is_valid_hostname(dns_name):
            errors.append(f"Invalid DNS name format: {dns_name}")

    # Check length
    full_record_name = f"{dns_name}.{domain}".rstrip('.') if dns_name else domain
    if len(full_record_name) > 255:
        errors.append(f"The full DNS name exceeds 255 characters: {full_record_name}")

    # Wildcard
    if '*' in dns_name:
        if not dns_name.startswith('*.'):
            errors.append("Wildcard records must start with '*.'")

    # Apex CNAME
    cname_valid, cname_err = prevent_cname_at_apex(dns_details)
    if not cname_valid:
        errors.append(cname_err)

    if errors:
        return False, errors
    return True, "All details are valid."


def split_txt_value(value):
    max_length = 255
    return [value[i:i+max_length] for i in range(0, len(value), max_length)]


# ------------------------------------------------------------------------------
# ROUTE53 CROSS-ACCOUNT HELPER
# ------------------------------------------------------------------------------
def call_list_hosted_zones(client):
    paginator = call_api(client.get_paginator, 'list_hosted_zones')
    zones = []
    for page in paginator.paginate():
        zones.extend(page['HostedZones'])
    return zones


def check_if_domain_in_hosted_zones(dns_details, client=None):
    domain = dns_details.get('domain', '').rstrip('.')
    if not domain:
        raise ValueError("Domain is missing in dns_details.")

    if client is None:
        client = get_route53_client()

    zones = call_list_hosted_zones(client)
    matched_zone_ids = []
    for z in zones:
        zone_name = z['Name'].rstrip('.')
        if zone_name == domain:
            matched_zone_ids.append(z['Id'])

    if matched_zone_ids:
        return True, matched_zone_ids
    return False, None


def record_exists(zone_id, record_name, record_type, client=None):
    if client is None:
        client = get_route53_client()
    record_name = record_name.rstrip('.') + '.'
    try:
        resp = call_api(
            client.list_resource_record_sets,
            HostedZoneId=zone_id,
            StartRecordName=record_name,
            StartRecordType=record_type,
            MaxItems="1"
        )
        recs = resp['ResourceRecordSets']
        if recs:
            first = recs[0]
            if first['Name'] == record_name and first['Type'] == record_type:
                return True, first
        return False, None
    except Exception as e:
        print(f"Error checking DNS records: {e}")
        raise


def spf_record_exists_in_zone(zone_id, client=None):
    if client is None:
        client = get_route53_client()
    paginator = call_api(client.get_paginator, 'list_resource_record_sets')
    spf_recs = []
    try:
        for page in paginator.paginate(HostedZoneId=zone_id):
            for rs in page['ResourceRecordSets']:
                if rs['Type'] == 'TXT':
                    for rr in rs.get('ResourceRecords', []):
                        val = rr['Value'].strip('"')
                        if val.startswith('v=spf1'):
                            spf_recs.append({'Name': rs['Name'], 'Value': val})
        return bool(spf_recs), spf_recs
    except Exception as e:
        print(f"Error checking SPF: {e}")
        raise


def check_route53_limits(zone_id, client=None):
    if client is None:
        client = get_route53_client()
    resp = call_api(client.get_hosted_zone, Id=zone_id)
    rcount = resp['HostedZone'].get('ResourceRecordSetCount', 0)
    if rcount >= 10000:
        raise Exception("Hosted zone record limit (10,000) reached.")


def conflicting_record_exists(zone_id, record_name, dns_type, client=None):
    if client is None:
        client = get_route53_client()
    paginator = client.get_paginator('list_resource_record_sets')
    try:
        for page in paginator.paginate(HostedZoneId=zone_id, StartRecordName=record_name):
            for rs in page['ResourceRecordSets']:
                if rs['Name'] == record_name and rs['Type'] != dns_type:
                    return True, rs['Type']
            if page['ResourceRecordSets'] and page['ResourceRecordSets'][-1]['Name'] != record_name:
                break
        return False, None
    except Exception as e:
        print(f"Error checking for conflicts: {e}")
        raise


def add_dns_record(dns_details, hosted_zone_id, client=None, account_id="unknown"):
    if client is None:
        client = get_route53_client()

    dns_name = dns_details.get('dns_name', '').strip().rstrip('.')
    domain = dns_details['domain'].strip().rstrip('.')

    try:
        domain = domain.encode('idna').decode('ascii')
        if dns_name:
            dns_name = dns_name.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError("Invalid internationalized domain name (IDN).")

    if dns_name:
        if dns_name.lower().endswith("." + domain.lower()):
            record_name = dns_name.rstrip('.') + '.'
        else:
            record_name = f"{dns_name}.{domain}".rstrip('.') + '.'
    else:
        record_name = domain + '.'

    dns_type = dns_details['dns_type'].upper()
    dns_value = dns_details['dns_value'].strip()

    if dns_type == 'TXT' and dns_value.startswith('"') and dns_value.endswith('"'):
        dns_value = dns_value[1:-1]

    if dns_type == 'CNAME' and not dns_name:
        print(f"[Account {account_id}] Cannot add CNAME at apex.")
        return 'invalid'

    conflict, existing_type = conflicting_record_exists(zone_id, record_name, dns_type, client)
    if conflict:
        print(f"[Account {account_id}] Cannot add {dns_type}; {existing_type} already exists at {record_name}.")
        return 'conflict'

    already_exists, _ = record_exists(zone_id, record_name, dns_type, client)
    if already_exists:
        print(f"[Account {account_id}] The {dns_type} record '{record_name}' already exists. Not adding.")
        return 'exists'

    # Build resource records
    if dns_type == 'MX':
        parts = dns_value.split(None, 1)
        if len(parts) != 2:
            raise ValueError("MX record requires priority and mail server.")
        priority, mail_server = parts
        records = [{'Value': f"{priority} {mail_server}"}]
    elif dns_type == 'TXT':
        txt_chunks = split_txt_value(dns_value)
        records = [{'Value': f'"{chunk}"'} for chunk in txt_chunks]
    elif dns_type in ['CAA', 'SRV']:
        records = [{'Value': dns_value}]
    else:
        records = [{'Value': dns_value}]

    change_batch = {
        'Comment': 'Automated DNS record creation',
        'Changes': [
            {
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': dns_type,
                    'TTL': 300,
                    'ResourceRecords': records
                }
            }
        ]
    }

    try:
        print(f"[Account {account_id}] Attempting to add {dns_type} => {record_name} ...")
        call_api(
            client.change_resource_record_sets,
            HostedZoneId=hosted_zone_id,
            ChangeBatch=change_batch
        )
        print(f"[Account {account_id}] DNS record '{record_name}' added successfully. Verifying presence...")

        time.sleep(2)
        recheck, _ = record_exists(zone_id=hosted_zone_id, record_name=record_name, record_type=dns_type, client=client)
        if recheck:
            print(f"[Account {account_id}] Verified record '{record_name}' => 'added'")
            return 'added'
        else:
            print(f"[Account {account_id}] Re-check failed => 'unknown'")
            return 'unknown'
    except client.exceptions.InvalidChangeBatch as e:
        err_msg = e.response['Error']['Message']
        if "but it already exists" in err_msg:
            print(f"[Account {account_id}] The {dns_type} record '{record_name}' exists after all => 'exists'")
            return 'exists'
        else:
            print(f"[Account {account_id}] Error adding DNS record: {e}")
            raise


# ------------------------------------------------------------------------------
# MAIN PROCESSING FUNCTION
# ------------------------------------------------------------------------------
def process_dns_request(description):
    """
    1) If any account can successfully add or find existing => short-circuit success
       returning (True, None, { "account_id":..., "zone_id":..., "dns_type":... }).
    2) If domain not found or error in every account => return failure with note.
    """
    dns_details = extract_dns_details(description)
    req_fields = ['dns_name', 'domain', 'dns_type', 'dns_value']
    missing = [f for f in req_fields if f not in dns_details or not dns_details[f]]
    if missing:
        return False, f"Missing DNS details: {', '.join(missing)}", None

    valid, validation_msg = validate_dns_details(dns_details)
    if not valid:
        if isinstance(validation_msg, list):
            return False, "Validation errors:\n" + "\n".join(validation_msg), None
        else:
            return False, f"Validation error: {validation_msg}", None

    if DNS_ACCOUNT_ROLE_MAPPINGS:
        try:
            acct_map = json.loads(DNS_ACCOUNT_ROLE_MAPPINGS)
            acct_map = reorder_mappings(acct_map)
        except Exception as e:
            print(f"Error parsing DNS_ACCOUNT_ROLE_MAPPINGS: {e}")
            acct_map = [{
                "account_id": os.getenv('CENTRAL_ADMIN_ACCOUNT_ID'),
                "role_name": os.getenv('CENTRAL_ADMIN_ROLE_NAME')
            }]
    else:
        acct_map = [{
            "account_id": os.getenv('CENTRAL_ADMIN_ACCOUNT_ID'),
            "role_name": os.getenv('CENTRAL_ADMIN_ROLE_NAME')
        }]

    fail_notes = []

    for mapping in acct_map:
        acct_id = mapping.get("account_id")
        role_name = mapping.get("role_name")
        print(f"Checking account {acct_id} with role {role_name}")

        client = get_route53_client(acct_id, role_name)

        # Check if domain in this account
        try:
            domain_found, hosted_zone_ids = check_if_domain_in_hosted_zones(dns_details, client)
            if not domain_found:
                fail_notes.append(f"Domain '{dns_details['domain']}' not found in account {acct_id}.")
                continue
        except Exception as e:
            fail_notes.append(f"Account {acct_id} domain check error: {e}")
            continue

        # If found => attempt
        zone_fail = []
        for zone_id in hosted_zone_ids:
            try:
                check_route53_limits(zone_id, client)
            except Exception as e:
                zone_fail.append(f"zone {zone_id} limit error: {str(e)}")
                continue

            # SPF check if needed
            if (dns_details['dns_type'].upper() == 'TXT'
               and dns_details['dns_value'].lower().startswith('v=spf1')):
                try:
                    spf_exists, _ = spf_record_exists_in_zone(zone_id, client)
                    if spf_exists:
                        zone_fail.append(f"zone {zone_id}: SPF record already exists.")
                        continue
                except Exception as e:
                    zone_fail.append(f"zone {zone_id} SPF check error => {e}")
                    continue

            try:
                res = add_dns_record(dns_details, zone_id, client, account_id=acct_id)
            except Exception as e:
                zone_fail.append(f"zone {zone_id} add error => {e}")
                continue

            if res in ['added', 'exists']:
                # success short-circuit
                print(f"[Account {acct_id}] => short-circuit success: {res}")
                success_info = {
                    "account_id": acct_id,
                    "zone_id": zone_id,
                    "dns_name": dns_details['dns_name'],
                    "dns_type": dns_details['dns_type'],
                    "domain": dns_details['domain'],
                    "result": res
                }
                return True, None, success_info
            else:
                zone_fail.append(f"zone {zone_id}: {res}")

        if zone_fail:
            fail_notes.append(f"Account {acct_id}: domain found, but all zones failed => {', '.join(zone_fail)}")
        else:
            fail_notes.append(f"Account {acct_id}: domain found but no zones updated (unknown).")

    if fail_notes:
        combined = "\n".join(fail_notes)
        note = f"No DNS record was added. Summary:\n{combined}"
        return False, note, None
    else:
        return False, "No accounts matched or domain not found anywhere. Not added.", None


# ------------------------------------------------------------------------------
# PREPARE RESPONSE & LAMBDA HANDLER
# ------------------------------------------------------------------------------
def prepare_public_response(dns_details, ticket_id, zendesk_agent, success_info=None):
    """
    If success_info is provided, we can display which account was used.
    """
    ticket_data = zendesk_agent.get(f"tickets/{ticket_id}")
    if ticket_data and 'ticket' in ticket_data:
        requester_id = ticket_data['ticket']['requester_id']
        user_data = zendesk_agent.get(f"users/{requester_id}")
        if user_data and 'user' in user_data:
            requester_name = user_data['user']['name']
            requester_first_name = requester_name.split()[0]
        else:
            requester_first_name = 'Customer'
    else:
        requester_first_name = 'Customer'

    dns_name = dns_details.get('dns_name', '')
    dns_type = dns_details.get('dns_type', '')
    dns_value = dns_details.get('dns_value', '')
    domain = dns_details.get('domain', '')

    # Build optional snippet showing account info
    account_snippet = ""
    if success_info and success_info.get("account_id"):
        acct_id = success_info["account_id"]
        zone_id = success_info["zone_id"]
        account_snippet = f"*AWS Account:* {acct_id}\n*Hosted Zone:* {zone_id}\n"

    # Format the reply
    public_response = textwrap.dedent(f"""\
        Dear {requester_first_name},

        Thank you for contacting the Central SaaS Support Team.

        We are pleased to confirm that the new DNS record has been added automatically:

        DNS Name: {dns_name}
        Record Type: {dns_type}
        Value: {dns_value}
        Domain: {domain}

        *Please note that DNS changes can take up to 24 hours (in rare cases, up to 48 hours) to propagate worldwide.*
        *Your new record might not be immediately visible in all regions.*

        {account_snippet}
        Should you require further assistance or have any questions, please do not hesitate to reach out to us.
        """).strip()

    return public_response


def lambda_handler(event, _):
    global PARAMETERS
    PARAMETERS = PARAMETERS or load_parameters(PARAMETER_NAME)
    os.environ.update(PARAMETERS)

    # Parse event
    body = event.get("body", None)
    if body is None:
        body = event
    if not isinstance(body, dict):
        body = json.loads(body)

    print(body)

    action = body.get("action", "")
    print(f"Running {action}")
    ticket_id = body.get("ticket_id")
    print(f"Ticket ID : {ticket_id}")

    payload = None

    if action and ticket_id:
        if action == "add_dns":
            zendesk_agent = zendesk_connection.ZendeskConnect()
            # Clear the "start" tag
            zendesk_agent.delete_tags(ticket_id, [START_TAG])
            # Mark as in-progress
            zendesk_agent.add_tags(ticket_id, [WIP_TAG])

            description = body.get("description", "")
            if not description:
                success = False
                internal_note = "No description found in the ticket."
                success_info = None
            else:
                success, internal_note, success_info = process_dns_request(description)

            # Cleanup
            zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
            zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])

            if success:
                # Mark as pending with a public reply
                zendesk_agent.add_tags(ticket_id, [ATLAS_CUSTOM_CLOSURE_TAG])
                dns_details = extract_dns_details(description)
                public_msg = prepare_public_response(dns_details, ticket_id, zendesk_agent, success_info=success_info)
                zendesk_agent.send_to_customer_macro(ticket_id, public_msg)
            else:
                # Domain not found => "on hold", but also add an internal note
                if internal_note and ("not found" in internal_note.lower()):
                    # 1) Write an internal note so we see the summary
                    zendesk_agent.write_internal_note(ticket_id, internal_note)
                    # 2) Check if ticket is already on hold
                    current_data = zendesk_agent.get(f"tickets/{ticket_id}")
                    if current_data and "ticket" in current_data:
                        if current_data["ticket"].get("status", "").lower() == "hold":
                            print("Ticket is already on hold; skip re-holding.")
                        else:
                            zendesk_agent.send_to_external_team_macro(
                                ticket_id,
                                reason="Automation adding necessary permissions",
                                offset=24,
                                external_team="team_internal",
                                escalation_target="tempo_other"
                            )
                    else:
                        # fallback
                        zendesk_agent.send_to_external_team_macro(
                            ticket_id,
                            reason="Automation adding necessary permissions",
                            offset=24,
                            external_team="team_internal",
                            escalation_target="tempo_other"
                        )
                else:
                    # Just add an internal note
                    if internal_note:
                        zendesk_agent.write_internal_note(ticket_id, internal_note)
                    else:
                        zendesk_agent.write_internal_note(ticket_id, f"{TAG_NAME} automation failed; no details found.")

            # Email summary
            summary_subj = f"DNS Automation Summary for Ticket {ticket_id}"
            if success:
                summary_body = (f"Ticket {ticket_id} processed with action '{action}'.\n\n"
                                f"Result: SUCCESS.\n"
                                f"Details:\nRecord was created or found to exist.\n\n"
                                f"Success Info: {success_info or 'N/A'}")
            else:
                summary_body = (f"Ticket {ticket_id} processed with action '{action}'.\n\n"
                                f"Result: FAILURE.\n"
                                f"Details:\n{internal_note or 'Unknown reason.'}")
            send_notification_email(summary_subj, summary_body)

        elif action == "add_dns_need_sc":
            sc_approval_scenario.send_for_approval(body, ticket_id)

        elif action == "add_dns_sc_received":
            is_approved = sc_approval_scenario.evaluate_approval(ticket_id)
            zendesk_agent = zendesk_connection.ZendeskConnect()
            zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
            zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])
            if is_approved:
                print("Performing approved action here.")
                zendesk_agent.add_tags(ticket_id, [ATLAS_CUSTOM_CLOSURE_TAG])
                pub_msg = "Your request is successfully fulfilled"
                zendesk_agent.send_to_customer_macro(ticket_id, pub_msg)
            else:
                fail_note = f"{TAG_NAME} automation aborted (not approved)."
                zendesk_agent.write_internal_note(ticket_id, fail_note)

        # Always respond 200 if we had a valid action
        return {
            'statusCode': 200,
            'body': json.dumps({"message": f"{action} is completed.", "payload": payload})
        }
    else:
        # Missing ticket_id or action
        return {
            'statusCode': 404,
            'body': json.dumps({
                "message": "ERROR: ticket_id or action not declared",
                "payload": payload
            })
        }


def load_parameters(parameter_name):
    ssm = boto3.client("ssm", region_name="us-east-1")
    resp = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
    return json.loads(resp["Parameter"]["Value"])


if __name__ == '__main__':
    # Quick local test
    test_event = {
        'action': 'add_dns',
        'ticket_id': '4565961',
        'description': 'DNS Name: test\nDomain: example.com\nDNS Type: A\nDNS Value: 1.2.3.4'
    }
    lambda_handler(test_event, None)
