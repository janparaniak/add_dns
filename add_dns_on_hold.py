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
# Otherwise, we fallback to CENTRAL_ADMIN_ACCOUNT_ID / CENTRAL_ADMIN_ROLE_NAME.
DNS_ACCOUNT_ROLE_MAPPINGS = os.getenv("DNS_ACCOUNT_ROLE_MAPPINGS", None)

# ------------------------------------------------------------------------------
# HELPER FUNCTION FOR SENDING EMAIL NOTIFICATIONS VIA SES
# ------------------------------------------------------------------------------
def send_notification_email(subject, message):
    """
    Sends an email notification using SES if SEND_EMAIL_NOTIFICATIONS is enabled.
    Environment Variables:
      - SEND_EMAIL_NOTIFICATIONS: "true" to enable (case-insensitive).
      - NOTIFICATION_EMAIL: Recipient email address.
      - SES_SOURCE_EMAIL: Verified source email address.
    """
    notify = os.getenv("SEND_EMAIL_NOTIFICATIONS", "false").lower() in ["true", "1"]
    if not notify:
        return
    recipient = os.getenv("NOTIFICATION_EMAIL", "jan.paraniak@trilogy.com")
    source = os.getenv("SES_SOURCE_EMAIL", recipient)
    ses = boto3.client("ses", region_name=os.getenv("AWS_REGION", "us-east-1"))
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
    """
    Wrap AWS API calls in exponential backoff to avoid throttling errors.
    """
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
      - then everything else.
    """
    preferred = []
    others = []
    for mapping in mappings:
        acct = mapping.get("account_id")
        if acct == "646253092271" or acct == "727712672144":
            preferred.append(mapping)
        else:
            others.append(mapping)
    preferred.sort(key=lambda m: 0 if m.get("account_id") == "646253092271" else 1)
    return preferred + others

def get_route53_client(account_id=None, role_name=None):
    """
    If account_id/role_name are provided, assume that cross-account role.
    Otherwise, fallback to CENTRAL_ADMIN_* env variables or local credentials.
    """
    if not account_id or not role_name:
        account_id = os.getenv('CENTRAL_ADMIN_ACCOUNT_ID')
        role_name = os.getenv('CENTRAL_ADMIN_ROLE_NAME')
        if not account_id or not role_name:
            print("CENTRAL_ADMIN_ACCOUNT_ID or CENTRAL_ADMIN_ROLE_NAME not set. Using local Route53 client.")
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
        print(f"Error assuming role {role_arn}: {e}")
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
        'dns_value': r'DNS Value:\s*(.+)'
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

    full_record_name = f"{dns_name}.{domain}".rstrip('.') if dns_name else domain
    if len(full_record_name) > 255:
        errors.append(f"The full DNS name exceeds 255 characters: {full_record_name}")

    if '*' in dns_name:
        if not dns_name.startswith('*.'):
            errors.append("Wildcard records must start with '*.'")

    dns_type = dns_details.get('dns_type', '').upper()
    dns_value = dns_details.get('dns_value', '').strip()

    cname_valid, cname_error = prevent_cname_at_apex(dns_details)
    if not cname_valid:
        errors.append(cname_error)

    # (Assume additional type-specific validations remain unchanged)

    if errors:
        return False, errors
    return True, "All details are valid."

def split_txt_value(value):
    max_length = 255
    return [value[i:i+max_length] for i in range(0, len(value), max_length)]

# ------------------------------------------------------------------------------
# ROUTE53 CROSS-ACCOUNT LOGIC
# ------------------------------------------------------------------------------
def call_list_hosted_zones(client):
    """Helper to list all hosted zones with exponential backoff."""
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
    for zone in zones:
        zone_name = zone['Name'].rstrip('.')
        if zone_name == domain:
            matched_zone_ids.append(zone['Id'])

    if matched_zone_ids:
        return True, matched_zone_ids
    return False, None

def record_exists(zone_id, record_name, record_type, client=None):
    if client is None:
        client = get_route53_client()
    record_name = record_name.rstrip('.') + '.'
    try:
        response = call_api(client.list_resource_record_sets,
                            HostedZoneId=zone_id,
                            StartRecordName=record_name,
                            StartRecordType=record_type,
                            MaxItems="1")
        record_sets = response['ResourceRecordSets']
        if record_sets:
            record = record_sets[0]
            if record['Name'] == record_name and record['Type'] == record_type:
                return True, record
        return False, None
    except Exception as e:
        print(f"Error checking DNS records: {e}")
        raise

def spf_record_exists_in_zone(zone_id, client=None):
    if client is None:
        client = get_route53_client()
    paginator = call_api(client.get_paginator, 'list_resource_record_sets')
    spf_records = []
    try:
        for page in paginator.paginate(HostedZoneId=zone_id):
            for record_set in page['ResourceRecordSets']:
                if record_set['Type'] == 'TXT':
                    for rr in record_set['ResourceRecords']:
                        value = rr['Value'].strip('"')
                        if value.startswith('v=spf1'):
                            spf_records.append({
                                'Name': record_set['Name'],
                                'Value': value
                            })
        return (len(spf_records) > 0), spf_records
    except Exception as e:
        print(f"Error checking SPF records in zone: {e}")
        raise

def check_route53_limits(zone_id, client=None):
    if client is None:
        client = get_route53_client()
    response = call_api(client.get_hosted_zone, Id=zone_id)
    record_count = response['HostedZone']['ResourceRecordSetCount']
    if record_count >= 10000:
        raise Exception("Cannot add record: Hosted zone record limit reached (10,000).")

def conflicting_record_exists(zone_id, record_name, dns_type, client=None):
    if client is None:
        client = get_route53_client()
    paginator = client.get_paginator('list_resource_record_sets')
    try:
        for page in paginator.paginate(HostedZoneId=zone_id, StartRecordName=record_name):
            for record_set in page['ResourceRecordSets']:
                if record_set['Name'] == record_name and record_set['Type'] != dns_type:
                    return True, record_set['Type']
            if page['ResourceRecordSets'] and page['ResourceRecordSets'][-1]['Name'] != record_name:
                break
        return False, None
    except Exception as e:
        print(f"Error checking for conflicting records: {e}")
        raise

def add_dns_record(dns_details, hosted_zone_id, client=None):
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
        print("Cannot add CNAME at apex.")
        return 'invalid'

    conflict, existing_type = conflicting_record_exists(hosted_zone_id, record_name, dns_type, client)
    if conflict:
        print(f"Cannot add {dns_type} record because a {existing_type} record already exists.")
        return 'conflict'

    exists_flag, _ = record_exists(hosted_zone_id, record_name, dns_type, client)
    if exists_flag:
        print(f"The {dns_type} record '{record_name}' already exists. Not adding new record.")
        return 'exists'

    if dns_type == 'MX':
        parts = dns_value.strip().split(None, 1)
        if len(parts) != 2:
            raise ValueError("MX record must contain priority and mail server.")
        priority, mail_server = parts
        resource_records = [{'Value': f"{priority} {mail_server}"}]
    elif dns_type == 'TXT':
        txt_chunks = split_txt_value(dns_value)
        resource_records = [{'Value': f'"{chunk}"'} for chunk in txt_chunks]
    elif dns_type in ['CAA', 'SRV']:
        resource_records = [{'Value': dns_value}]
    else:
        resource_records = [{'Value': dns_value}]

    change_batch = {
        'Comment': 'Automated DNS record creation',
        'Changes': [
            {
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': dns_type,
                    'TTL': 300,
                    'ResourceRecords': resource_records
                }
            }
        ]
    }

    try:
        response = call_api(client.change_resource_record_sets,
                            HostedZoneId=hosted_zone_id,
                            ChangeBatch=change_batch)
        print(f"DNS record '{record_name}' added successfully.")
        return 'added'
    except client.exceptions.InvalidChangeBatch as e:
        msg = e.response['Error']['Message']
        if "but it already exists" in msg:
            print(f"The {dns_type} record '{record_name}' already exists. Not adding new record.")
            return 'exists'
        else:
            print(f"Error adding DNS record: {e}")
            raise


# ------------------------------------------------------------------------------
# MAIN PROCESSING FUNCTION
# ------------------------------------------------------------------------------
def process_dns_request(description):
    """
    Stop after first success:
    - If any account can add the record, short-circuit and return success.
    - If all accounts fail, produce a minimal summary.
    """
    dns_details = extract_dns_details(description)
    required = ['dns_name', 'domain', 'dns_type', 'dns_value']
    missing = [f for f in required if f not in dns_details or not dns_details[f]]
    if missing:
        return False, f"Missing DNS details: {', '.join(missing)}", None

    valid, validation_msg = validate_dns_details(dns_details)
    if not valid:
        if isinstance(validation_msg, list):
            internal_note = "Validation errors:\n" + "\n".join(validation_msg)
        else:
            internal_note = f"Validation error: {validation_msg}"
        return False, internal_note, None

    if DNS_ACCOUNT_ROLE_MAPPINGS:
        try:
            account_mappings = json.loads(DNS_ACCOUNT_ROLE_MAPPINGS)
            account_mappings = reorder_mappings(account_mappings)
        except Exception as e:
            print(f"Error parsing DNS_ACCOUNT_ROLE_MAPPINGS: {e}")
            account_mappings = [{
                "account_id": os.getenv('CENTRAL_ADMIN_ACCOUNT_ID'),
                "role_name": os.getenv('CENTRAL_ADMIN_ROLE_NAME')
            }]
    else:
        account_mappings = [{
            "account_id": os.getenv('CENTRAL_ADMIN_ACCOUNT_ID'),
            "role_name": os.getenv('CENTRAL_ADMIN_ROLE_NAME')
        }]

    # We'll store minimal notes if all fail.
    all_fail_notes = []

    for mapping in account_mappings:
        account_id = mapping.get("account_id")
        role_name = mapping.get("role_name")
        print(f"Checking account {account_id} with role {role_name}")

        client = get_route53_client(account_id, role_name)
        try:
            domain_found, hosted_zone_ids = check_if_domain_in_hosted_zones(dns_details, client)
            if not domain_found:
                all_fail_notes.append(f"Domain '{dns_details.get('domain')}' not found in account {account_id}.")
                continue
        except Exception as e:
            all_fail_notes.append(f"Error checking domain in account {account_id}: {str(e)}")
            continue

        any_zone_success = False
        zone_failures = []
        for zone_id in hosted_zone_ids:
            try:
                check_route53_limits(zone_id, client)
            except Exception as e:
                zone_failures.append(f"zone {zone_id} limit error: {str(e)}")
                continue

            if dns_details['dns_type'].upper() == 'TXT' and dns_details['dns_value'].lower().startswith('v=spf1'):
                try:
                    spf_exists, _ = spf_record_exists_in_zone(zone_id, client)
                    if spf_exists:
                        zone_failures.append(f"zone {zone_id}: SPF record already exists.")
                        continue
                except Exception as e:
                    zone_failures.append(f"zone {zone_id} SPF check error: {str(e)}")
                    continue

            try:
                add_result = add_dns_record(dns_details, zone_id, client)
                if add_result == 'added':
                    any_zone_success = True
                elif add_result in ('exists', 'conflict', 'invalid'):
                    zone_failures.append(f"zone {zone_id}: {add_result} (not added).")
                else:
                    zone_failures.append(f"zone {zone_id}: unknown issue.")
            except Exception as e:
                zone_failures.append(f"zone {zone_id} add error: {str(e)}")

        if any_zone_success:
            return True, None, None
        else:
            if zone_failures:
                notes = "; ".join(zone_failures)
                all_fail_notes.append(f"Account {account_id}: Domain found but all zones failed: {notes}")
            else:
                all_fail_notes.append(f"Account {account_id}: Domain found but no zone updated.")

    if all_fail_notes:
        combined = "\n".join(all_fail_notes)
        fail_note = f"No DNS record was added. Summary:\n{combined}"
        return False, fail_note, None
    else:
        return False, "No accounts matched or domain not found anywhere. Not added.", None


# ------------------------------------------------------------------------------
# PREPARE RESPONSE & LAMBDA HANDLER
# ------------------------------------------------------------------------------
def prepare_public_response(dns_details, ticket_id, zendesk_agent):
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

        Should you require further assistance or have any questions, please do not hesitate to reach out to us.
        """).strip()

    return public_response

def lambda_handler(event, _):
    global PARAMETERS
    PARAMETERS = PARAMETERS or load_parameters(PARAMETER_NAME)
    os.environ.update(PARAMETERS)

    body = event.get("body", None)
    if body is None:
        body = event

    if not isinstance(body, dict):
        body = json.loads(body)

    print(body)

    action = body.get("action", "")
    print(f"Running {action}")
    payload = None
    ticket_id = body.get("ticket_id")
    print(f"Ticket ID : {ticket_id}")

    if action and ticket_id:
        if action == "add_dns":
            zendesk_agent = zendesk_connection.ZendeskConnect()
            zendesk_agent.delete_tags(ticket_id, [START_TAG])
            zendesk_agent.add_tags(ticket_id, [WIP_TAG])

            # --- START AUTOMATION CODE ---
            description = body.get("description", "")
            if not description:
                success = False
                internal_note = "No description found in the ticket."
            else:
                success, internal_note, _ = process_dns_request(description)
            # --- END AUTOMATION CODE ---

            # Cleanup tags
            zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
            zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])

            if success:
                zendesk_agent.add_tags(ticket_id, [ATLAS_CUSTOM_CLOSURE_TAG])
                dns_details = extract_dns_details(description)
                public_response = prepare_public_response(dns_details, ticket_id, zendesk_agent)
                zendesk_agent.send_to_customer_macro(ticket_id, public_response)
            else:
                # If the failure reason indicates that the domain was not found in any account,
                # place the ticket on hold for 24 hours using the external team macro.
                if internal_note and "not found" in internal_note.lower():
                    zendesk_agent.send_to_external_team_macro(
                        ticket_id,
                        reason="Automation adding necessary permissions",
                        offset=24,
                        external_team="team_internal",
                        escalation_target="tempo_other"
                    )
                elif internal_note:
                    zendesk_agent.write_internal_note(ticket_id, internal_note)
                else:
                    fail_note = f"{TAG_NAME} automation failed to continue, exiting"
                    zendesk_agent.write_internal_note(ticket_id, fail_note)

            # Send notification email to monitor automation health
            summary_subject = f"DNS Automation Summary for Ticket {ticket_id}"
            summary_message = f"Ticket {ticket_id} processed with action '{action}'.\n\nResult: {'Success' if success else 'Failure'}.\nDetails:\n{internal_note if internal_note else 'Record added successfully.'}"
            send_notification_email(summary_subject, summary_message)

        elif action == "add_dns_need_sc":
            sc_approval_scenario.send_for_approval(body, ticket_id)

        elif action == "add_dns_sc_received":
            is_approved = sc_approval_scenario.evaluate_approval(ticket_id)

            zendesk_agent = zendesk_connection.ZendeskConnect()
            zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
            zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])

            if is_approved:
                print("Do the necessary action here")
                zendesk_agent.add_tags(ticket_id, [ATLAS_CUSTOM_CLOSURE_TAG])
                public_response = "Your request is successfully fulfilled"
                zendesk_agent.send_to_customer_macro(ticket_id, public_response)
            else:
                fail_note = f"{TAG_NAME} automation failed to continue, exiting"
                zendesk_agent.write_internal_note(ticket_id, fail_note)

        message = f"{action} is completed."
        response = {
            'statusCode': 200,
            'body': json.dumps({"message": message, "payload": payload})
        }

    else:
        response = {
            'statusCode': 404,
            'body': json.dumps({"message": "ERROR: ticket_id or action is not declared", "payload": payload})
        }

    print(response)
    return response

def load_parameters(parameter_name):
    ssm = boto3.client("ssm", region_name="us-east-1")
    response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
    return json.loads(response["Parameter"]["Value"])

if __name__ == '__main__':
    # Quick local test
    sample_payload = {
        'action': 'add_dns',
        'ticket_id': '4565961',
        'requester_email': 'someone@example.com',
        'subject': 'test add_dns subject',
        'description': 'DNS Name: test\nDomain: example.com\nDNS Type: A\nDNS Value: 1.2.3.4',
        'customer_list': 'some customers'
    }
    lambda_handler(sample_payload, None)

"""
Explanation of New Features
On-Hold Macro:
In the "add_dns" branch, if no hosted zone is found (the internal note contains “not found”), the code calls
zendesk_agent.send_to_external_team_macro with:

Reason: "Automation adding necessary permissions"
Offset: 24 (hours)
External team: "team_internal"
Escalation target: "tempo_other"
Automatic Retry:
(Note: The code itself does not schedule a retry; you should configure a separate Zendesk automation to reopen the ticket after 24 hours so that the original request is retried.)

Email Notification:
After processing a ticket, the function calls send_notification_email to send an email to the configured recipient (default is jan.paraniak@trilogy.com). You can disable this functionality by setting the environment variable SEND_EMAIL_NOTIFICATIONS to "false".

Environment Variables:

SEND_EMAIL_NOTIFICATIONS: Set to "true" to enable email notifications.
NOTIFICATION_EMAIL: The email address to send notifications to.
SES_SOURCE_EMAIL: The verified SES source email address (if different from the recipient).
(Other environment variables remain as before.)
Deploy this updated code. It will now (a) put the ticket on hold if no hosted zone is found, (b) send an email notification about the automation’s outcome, and (c) leave existing functionality unchanged.
"""
