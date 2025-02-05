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
    # Sort so that 646253092271 is first, 727712672144 is second
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
        # Fall back to local route53 client
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

    # If user typed '@' for dns_name, interpret as apex
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

    # Check apex CNAME
    cname_valid, cname_error = prevent_cname_at_apex(dns_details)
    if not cname_valid:
        errors.append(cname_error)

    reserved_names = ['_spf', '_dmarc', '_domainkey']
    # No direct ban, but you can customize if needed

    # Type-specific checks
    if dns_type == "A":
        try:
            ip = ipaddress.IPv4Address(dns_value)
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast:
                errors.append(f"IP address {dns_value} is a private or reserved address.")
        except ipaddress.AddressValueError:
            errors.append(f"Invalid IPv4 address for A record: {dns_value}")

    elif dns_type == "AAAA":
        try:
            ip = ipaddress.IPv6Address(dns_value)
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast:
                errors.append(f"IP address {dns_value} is a private or reserved address.")
        except ipaddress.AddressValueError:
            errors.append(f"Invalid IPv6 address for AAAA record: {dns_value}")

    elif dns_type in ["CNAME", "NS"]:
        if not is_valid_hostname(dns_value):
            errors.append(f"Invalid FQDN format for {dns_type} record: {dns_value}")

    elif dns_type == "MX":
        parts = dns_value.split(None, 1)
        if len(parts) != 2:
            errors.append(f"Invalid MX record format: {dns_value}")
        else:
            priority_str, mail_server = parts
            try:
                priority = int(priority_str)
                if not (0 <= priority <= 65535):
                    errors.append(f"MX record priority must be between 0 and 65535: {priority}")
            except ValueError:
                errors.append(f"Invalid MX record priority: {priority_str}")
            if not is_valid_hostname(mail_server):
                errors.append(f"Invalid mail server hostname in MX record: {mail_server}")

    elif dns_type == "TXT":
        # Minor SPF checks
        if 'v=spf1' in dns_value.lower():
            if 'ptr' in dns_value.lower():
                errors.append("Usage of 'ptr' mechanism in SPF records is discouraged.")

    elif dns_type == "CAA":
        parts = dns_value.split(None, 2)
        if len(parts) != 3:
            errors.append(f"Invalid CAA record format: {dns_value}")
        else:
            flags_str, tag, value = parts
            try:
                flags = int(flags_str)
                if not (0 <= flags <= 255):
                    errors.append(f"CAA flags must be between 0 and 255: {flags}")
            except ValueError:
                errors.append(f"Invalid CAA flags: {flags_str}")
            valid_tags = ['issue', 'issuewild', 'iodef']
            if tag.lower() not in valid_tags:
                errors.append(f"Invalid CAA tag: {tag}")
            if not (value.startswith('"') and value.endswith('"')):
                errors.append(f"CAA value must be enclosed in double quotes: {value}")

    elif dns_type == "SRV":
        parts = dns_value.strip().split()
        if len(parts) != 4:
            errors.append(f"Invalid SRV record format: {dns_value}")
        else:
            priority_str, weight_str, port_str, target = parts
            try:
                priority = int(priority_str)
                if not (0 <= priority <= 65535):
                    errors.append(f"SRV record priority must be 0-65535: {priority}")
            except ValueError:
                errors.append(f"Invalid SRV priority: {priority_str}")
            try:
                weight = int(weight_str)
                if not (0 <= weight <= 65535):
                    errors.append(f"SRV record weight must be 0-65535: {weight}")
            except ValueError:
                errors.append(f"Invalid SRV weight: {weight_str}")
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    errors.append(f"SRV record port must be 1-65535: {port}")
            except ValueError:
                errors.append(f"Invalid SRV port: {port_str}")
            if not is_valid_hostname(target):
                errors.append(f"Invalid target hostname in SRV record: {target}")

    else:
        errors.append(f"Unsupported or disallowed DNS type: {dns_type}")

    # Additional DMARC check
    if dns_type == 'TXT' and dns_name.lower().startswith('_dmarc'):
        if not dns_value.lower().startswith('v=dmarc1;'):
            errors.append("Invalid DMARC record: Must start with 'v=DMARC1;'")

    if errors:
        return False, errors
    return True, "All details are valid."


def split_txt_value(value):
    max_length = 255
    return [value[i:i+max_length] for i in range(0, len(value), max_length)]


# ------------------------------------------------------------------------------ 
# ROUTE53 CROSS-ACCOUNT LOGIC
# ------------------------------------------------------------------------------
def check_if_domain_in_hosted_zones(dns_details, client=None):
    """
    Return (True, [zoneIDs]) if the domain is found in the given account's hosted zones,
    otherwise (False, None).
    """
    domain = dns_details.get('domain', '').rstrip('.')
    if not domain:
        raise ValueError("Domain is missing in dns_details.")

    if client is None:
        client = get_route53_client()

    matched_zone_ids = []
    paginator = call_api(client.get_paginator, 'list_hosted_zones')
    try:
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                zone_name = zone['Name'].rstrip('.')
                if zone_name == domain:
                    matched_zone_ids.append(zone['Id'])
    except Exception as e:
        print(f"Error listing hosted zones: {e}")
        raise

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
        if spf_records:
            return True, spf_records
        else:
            return False, None
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
    """
    Attempt to add the DNS record in the specified hosted zone ID.
    Returns 'added','exists','conflict','invalid', or '???'
    """
    if client is None:
        client = get_route53_client()

    dns_name = dns_details.get('dns_name', '').strip().rstrip('.')
    domain = dns_details['domain'].strip().rstrip('.')

    # Handle IDNs
    try:
        domain = domain.encode('idna').decode('ascii')
        if dns_name:
            dns_name = dns_name.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError("Invalid internationalized domain name (IDN).")

    # Avoid double-appending the domain
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

    record_exists_flag, _ = record_exists(hosted_zone_id, record_name, dns_type, client)
    if record_exists_flag:
        print(f"The {dns_type} record '{record_name}' already exists. Not adding new record.")
        return 'exists'

    # Build resource record data
    resource_records = []
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
    1. Extract DNS details (name, domain, type, value).
    2. Validate them.
    3. For each account in DNS_ACCOUNT_ROLE_MAPPINGS (or fallback):
       a. Check if domain is found
       b. If found, attempt to add record in each matching hosted zone
    4. Return success/failure plus internal notes
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

    # Build the account mappings
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

    success_for_any_account = False
    overall_failure_notes = []

    # Go through each account mapping
    for mapping in account_mappings:
        account_id = mapping.get("account_id")
        role_name = mapping.get("role_name")
        print(f"Checking account {account_id} with role {role_name}")
        client = get_route53_client(account_id, role_name)

        # Check if domain is found in this account
        try:
            domain_exists, hosted_zone_ids = check_if_domain_in_hosted_zones(dns_details, client)
            if not domain_exists:
                overall_failure_notes.append(
                    f"Domain '{dns_details.get('domain')}' not found in account {account_id}."
                )
                # Move on to the next account
                continue
        except Exception as e:
            overall_failure_notes.append(f"Error checking domain in account {account_id}: {str(e)}")
            continue

        # If domain is found, attempt to add record in each matching zone
        account_success = False
        failure_notes = []
        for zone_id in hosted_zone_ids:
            try:
                check_route53_limits(zone_id, client)
            except Exception as e:
                failure_notes.append(f"Hosted zone limit error for zone {zone_id} in account {account_id}: {str(e)}")
                continue

            # If a TXT record is SPF
            dns_type = dns_details.get('dns_type', '').upper()
            dns_value = dns_details.get('dns_value', '').strip()
            if dns_type == 'TXT' and dns_value.lower().startswith('v=spf1'):
                try:
                    spf_exists, spf_records = spf_record_exists_in_zone(zone_id, client)
                    if spf_exists:
                        failure_notes.append(
                            f"An SPF record already exists in zone {zone_id} in account {account_id}. Skipped."
                        )
                        continue
                except Exception as e:
                    failure_notes.append(f"Error checking SPF in zone {zone_id} in account {account_id}: {str(e)}")
                    continue

            # Attempt to add
            try:
                result = add_dns_record(dns_details, zone_id, client)
                if result == 'added':
                    account_success = True
                elif result in ['exists', 'conflict', 'invalid']:
                    failure_notes.append(
                        f"Could not add record in zone {zone_id} (reason: {result})."
                    )
                else:
                    failure_notes.append(
                        f"Record not added in zone {zone_id} for unknown reason."
                    )
            except Exception as e:
                failure_notes.append(f"Error adding DNS record to zone {zone_id}: {str(e)}")

        if account_success:
            success_for_any_account = True
            if failure_notes:
                # partial success in this account
                notes = "\n".join(failure_notes)
                overall_failure_notes.append(
                    f"Account {account_id}: Some zones succeeded, some failed:\n{notes}"
                )
        else:
            # No zone in this account succeeded
            if failure_notes:
                combined_fail = "\n".join(failure_notes)
                overall_failure_notes.append(
                    f"Account {account_id}: All zones failed.\n{combined_fail}"
                )
            else:
                # Domain was found, but no zone was updated
                overall_failure_notes.append(
                    f"Account {account_id}: Domain found but no zone updated."
                )

    # After checking all accounts
    if not success_for_any_account:
        notes = "\n".join(overall_failure_notes)
        internal_note = f"Did not add the record to any hosted zone.\n{notes}"
        return False, internal_note, None
    else:
        # At least one zone in at least one account succeeded
        if overall_failure_notes:
            partial = "Some accounts/zones failed. At least one succeeded.\n"
            partial += "\n".join(overall_failure_notes)
            return True, partial, None
        else:
            return True, None, None


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

    # Restored the old style formatting
    public_response = textwrap.dedent(f"""\
        Dear {requester_first_name},

        Thank you for contacting the Central SaaS Support Team.

        We are pleased to confirm that the new DNS record has been added automatically:
        
        ```
        DNS Name: {dns_name}
        Record Type: {dns_type}
        Value: {dns_value}
        Domain: {domain}
        ```
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
                # The macro is assumed to set the ticket to pending
            else:
                if internal_note:
                    zendesk_agent.write_internal_note(ticket_id, internal_note)
                else:
                    fail_note = f"{TAG_NAME} automation failed to continue, exiting"
                    zendesk_agent.write_internal_note(ticket_id, fail_note)

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
        response = {'statusCode': 200, 'body': json.dumps({"message": message, "payload": payload})}

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
