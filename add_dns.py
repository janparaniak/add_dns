import json
import os
import re
import textwrap
import time
import boto3
import botocore.exceptions

import zendesk_connection
import openai_ops
import sc_approval_scenario

TAG_NAME = "add_dns"

START_TAG = f"{TAG_NAME}-trigger"
WIP_TAG = f"{TAG_NAME}-trigger-processing"
COMPLETED_TAG = f"{TAG_NAME}-trigger-processed"
ATLAS_CUSTOM_CLOSURE_TAG = "atlas-ticket-custom-closure"

# Tag to mark that we've already had a successful run (so we don't do another public reply)
DNS_RECORD_SUCCESS_TAG = "dns-record-success"

# Optional tag to ensure we don't repeatedly put on hold
HOLD_TAG = "dns-hold-placed"

PARAMETER_NAME = f"{TAG_NAME}_parameters"
PARAMETERS = None

DNS_ACCOUNT_ROLE_MAPPINGS = os.getenv("DNS_ACCOUNT_ROLE_MAPPINGS", None)

def post_internal_note_once(ticket_id, content, zendesk_agent):
    """
    Post an internal note, but only if the last internal note isn't the same text.
    """
    time.sleep(1)

    comments_data = zendesk_agent.get(f"tickets/{ticket_id}/comments?sort_order=desc")
    if comments_data and "comments" in comments_data:
        comments = comments_data["comments"]
        if len(comments) > 0:
            latest_comment = comments[0]
            # Check if it's an internal note and has the same body
            if (latest_comment.get("public") is False and
                latest_comment.get("body", "").strip() == content.strip()):
                print("Skipping repeated internal note. The last internal note is identical.")
                return
    # Otherwise, post the note as usual
    zendesk_agent.write_internal_note(ticket_id, content)


def send_notification_email(subject, message):
    notify = os.getenv("SEND_EMAIL_NOTIFICATIONS", "false").lower() in ["true", "1"]
    if not notify:
        return
    recipient = os.getenv("NOTIFICATION_EMAIL", "jan.paraniak@trilogy.com")
    source = os.getenv("SES_SOURCE_EMAIL", recipient)
    region = os.getenv("AWS_REGION", "us-east-1")
    ses = boto3.client("ses", region_name=region)
    try:
        ses.send_email(
            Source=source,
            Destination={"ToAddresses": [recipient]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": message}}
            },
        )
        print(f"Email notification sent to {recipient}")
    except Exception as e:
        print(f"Failed to send email notification: {e}")


def call_api(func, *args, **kwargs):
    max_retries = 5
    delay = 1
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"].get("Code", "")
            if code in ["Throttling", "RateExceeded", "PriorRequestNotComplete"]:
                print(f"Throttling error: {e}; retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
            else:
                raise
    return func(*args, **kwargs)


def reorder_mappings(mappings):
    preferred = []
    others = []
    for m in mappings:
        acct_id = m.get("account_id")
        if acct_id == "646253092271" or acct_id == "727712672144":
            preferred.append(m)
        else:
            others.append(m)
    # sort so 646253092271 is index 0, 727712672144 is index 1
    preferred.sort(key=lambda x: 0 if x.get("account_id") == "646253092271" else 1)
    return preferred + others


def get_route53_client(account_id=None, role_name=None):
    if not account_id or not role_name:
        account_id = os.getenv("CENTRAL_ADMIN_ACCOUNT_ID")
        role_name = os.getenv("CENTRAL_ADMIN_ROLE_NAME")
        if not account_id or not role_name:
            print("No cross-account role set; using local credentials.")
            return boto3.client("route53")

    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        assumed = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="LambdaDNSManagerSession")
        creds = assumed["Credentials"]
        return boto3.client(
            "route53",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except Exception as e:
        print(f"Error assuming role {role_arn}: {e}, falling back to local route53 client.")
        return boto3.client("route53")


def extract_dns_details(description):
    dns_details = {}
    patterns = {
        "dns_name": r"DNS Name:\s*(.+)",
        "domain": r"Domain:\s*(.+)",
        "dns_type": r"DNS Type:\s*(.+)",
        "dns_value": r"DNS Value:\s*(.+)",
    }
    for k, pat in patterns.items():
        m = re.search(pat, description, re.IGNORECASE)
        if m:
            dns_details[k] = m.group(1).strip()

    if dns_details.get("dns_name") == "@":
        dns_details["dns_name"] = ""
    return dns_details


def is_valid_hostname(hn):
    if hn.endswith("."):
        hn = hn[:-1]
    if len(hn) > 253:
        return False
    allowed = re.compile(r"^(?!-)[A-Z\d_-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hn.split("."))


def prevent_cname_at_apex(d):
    t = d.get("dns_type", "").upper()
    n = d.get("dns_name", "").strip()
    if t == "CNAME" and not n:
        return False, "Cannot add CNAME at apex."
    return True, ""


def validate_dns_details(d):
    errs = []
    domain = d.get("domain", "")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        errs.append(f"Invalid domain name (IDN): {domain}")

    if not domain or not is_valid_hostname(domain):
        errs.append(f"Invalid domain format: {domain}")

    dn = d.get("dns_name", "")
    if dn:
        try:
            dn = dn.encode("idna").decode("ascii")
        except UnicodeError:
            errs.append(f"Invalid DNS name (IDN): {dn}")
        if not is_valid_hostname(dn):
            errs.append(f"Invalid DNS name format: {dn}")

    full_record_name = f"{dn}.{domain}".rstrip('.') if dn else domain
    if len(full_record_name) > 255:
        errs.append(f"The full DNS name exceeds 255 characters: {full_record_name}")

    c_ok, c_msg = prevent_cname_at_apex(d)
    if not c_ok:
        errs.append(c_msg)

    if errs:
        return False, errs
    return True, "All details valid"


def split_txt_value(val):
    max_len = 255
    return [val[i:i+max_len] for i in range(0, len(val), max_len)]


def call_list_hosted_zones(client):
    pag = call_api(client.get_paginator, "list_hosted_zones")
    zones = []
    for page in pag.paginate():
        zones.extend(page["HostedZones"])
    return zones


def check_if_domain_in_hosted_zones(d, client=None):
    domain = d.get("domain", "").rstrip(".")
    if not domain:
        raise ValueError("Missing domain in dns_details.")
    if client is None:
        client = get_route53_client()
    zones = call_list_hosted_zones(client)
    matched = []
    for z in zones:
        z_name = z["Name"].rstrip(".")
        if z_name == domain:
            matched.append(z["Id"])
    if matched:
        return True, matched
    return False, None


def record_exists(zone_id, record_name, record_type, client=None):
    if client is None:
        client = get_route53_client()
    rn = record_name.rstrip('.') + '.'
    try:
        resp = call_api(client.list_resource_record_sets,
                        HostedZoneId=zone_id,
                        StartRecordName=rn,
                        StartRecordType=record_type,
                        MaxItems="1")
        sets = resp["ResourceRecordSets"]
        if sets:
            first = sets[0]
            if first["Name"] == rn and first["Type"] == record_type:
                return True, first
        return False, None
    except Exception as e:
        print(f"Error checking record: {e}")
        raise


def spf_record_exists_in_zone(zone_id, client=None):
    if client is None:
        client = get_route53_client()
    pag = call_api(client.get_paginator, "list_resource_record_sets")
    found_spf = []
    try:
        for page in pag.paginate(HostedZoneId=zone_id):
            for rs in page["ResourceRecordSets"]:
                if rs["Type"] == "TXT":
                    for rr in rs.get("ResourceRecords", []):
                        val = rr["Value"].strip('"')
                        if val.startswith("v=spf1"):
                            found_spf.append(rs)
        return bool(found_spf), found_spf
    except Exception as e:
        print(f"Error checking SPF: {e}")
        raise


def check_route53_limits(zone_id, client=None):
    if client is None:
        client = get_route53_client()
    resp = call_api(client.get_hosted_zone, Id=zone_id)
    count = resp["HostedZone"].get("ResourceRecordSetCount", 0)
    if count >= 10000:
        raise Exception("Hosted zone limit reached (10000).")


def conflicting_record_exists(zone_id, record_name, dns_type, client=None):
    if client is None:
        client = get_route53_client()
    pag = client.get_paginator("list_resource_record_sets")
    try:
        for page in pag.paginate(HostedZoneId=zone_id, StartRecordName=record_name):
            for rs in page["ResourceRecordSets"]:
                if rs["Name"] == record_name and rs["Type"] != dns_type:
                    return True, rs["Type"]
            if page["ResourceRecordSets"] and page["ResourceRecordSets"][-1]["Name"] != record_name:
                break
        return False, None
    except Exception as e:
        print(f"Error checking conflicts: {e}")
        raise


def add_dns_record(dns_details, zone_id, client=None, account_id="unknown"):
    if client is None:
        client = get_route53_client()

    dn = dns_details.get("dns_name", "").strip().rstrip(".")
    domain = dns_details["domain"].strip().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
        if dn:
            dn = dn.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid IDN domain/dns_name")

    if dn:
        if dn.lower().endswith("." + domain.lower()):
            record_name = dn.rstrip('.') + '.'
        else:
            record_name = f"{dn}.{domain}".rstrip('.') + '.'
    else:
        record_name = domain + '.'

    dtype = dns_details["dns_type"].upper()
    dval = dns_details["dns_value"].strip()

    if dtype == "TXT" and dval.startswith('"') and dval.endswith('"'):
        dval = dval[1:-1]

    if dtype == "CNAME" and not dn:
        print(f"[Acct {account_id}] CNAME at apex => invalid")
        return "invalid"

    conf, ex_type = conflicting_record_exists(zone_id, record_name, dtype, client)
    if conf:
        print(f"[Acct {account_id}] {dtype} conflict => found {ex_type} at {record_name}")
        return "conflict"

    ex, _ = record_exists(zone_id, record_name, dtype, client)
    if ex:
        print(f"[Acct {account_id}] {dtype} record '{record_name}' already exists => 'exists'")
        return "exists"

    if dtype == "MX":
        parts = dval.split(None, 1)
        if len(parts) != 2:
            raise ValueError("MX must have priority + server.")
        rr = [{"Value": f"{parts[0]} {parts[1]}"}]
    elif dtype == "TXT":
        chunks = split_txt_value(dval)
        rr = [{"Value": f'"{c}"'} for c in chunks]
    elif dtype in ["CAA", "SRV"]:
        rr = [{"Value": dval}]
    elif dtype == "NS":
        # If you want to fail whenever "for:" shows up, do something like:
        # Split the user-provided string by commas/whitespace
        ns_tokens = re.split(r"[,\s]+", dval)
        # Build one ResourceRecord per token, ignoring blanks
        rr = [{"Value": token.strip()} for token in ns_tokens if token.strip()]

    else:
        rr = [{"Value": dval}]

    change_batch = {
        "Comment": "Automated DNS creation",
        "Changes": [
            {
                "Action": "CREATE",
                "ResourceRecordSet": {
                    "Name": record_name,
                    "Type": dtype,
                    "TTL": 300,
                    "ResourceRecords": rr
                }
            }
        ]
    }

    print(f"[Acct {account_id}] Attempting to add {dtype} => {record_name}")
    try:
        call_api(client.change_resource_record_sets, HostedZoneId=zone_id, ChangeBatch=change_batch)
        print(f"[Acct {account_id}] Added '{record_name}', verifying..")
        time.sleep(2)
        recheck, _ = record_exists(zone_id, record_name, dtype, client)
        if recheck:
            print(f"[Acct {account_id}] Verified => 'added'")
            return "added"
        else:
            print(f"[Acct {account_id}] recheck => 'unknown'")
            return "unknown"
    except client.exceptions.InvalidChangeBatch as e:
        em = e.response["Error"]["Message"]
        if "already exists" in em:
            print(f"[Acct {account_id}] => 'exists'")
            return "exists"
        else:
            print(f"[Acct {account_id}] Error => {e}")
            raise


def process_dns_request(description):
    dns_details = extract_dns_details(description)
    required = ["dns_name", "domain", "dns_type", "dns_value"]
    missing = [f for f in required if f not in dns_details or not dns_details[f]]
    if missing:
        return False, f"Missing DNS details: {', '.join(missing)}", None

    # A small check if the CNAME record matches values
    if dns_details["dns_type"].upper() == "CNAME":
        val = dns_details["dns_value"].lower()
        if "ns-" in val and ("," in val or " " in val):
            return False, (
                "User selected CNAME, but the DNS Value looks like nameservers. "
                "Please confirm if this should be an NS record."
            ), None

    valid, msg = validate_dns_details(dns_details)
    if not valid:
        if isinstance(msg, list):
            return False, "Validation errors:\n" + "\n".join(msg), None
        else:
            return False, f"Validation error: {msg}", None

    # parse mappings
    if DNS_ACCOUNT_ROLE_MAPPINGS:
        try:
            raw = json.loads(DNS_ACCOUNT_ROLE_MAPPINGS)
            raw = reorder_mappings(raw)
        except Exception as e:
            print(f"Error with DNS_ACCOUNT_ROLE_MAPPINGS => {e}")
            raw = [{
                "account_id": os.getenv("CENTRAL_ADMIN_ACCOUNT_ID"),
                "role_name": os.getenv("CENTRAL_ADMIN_ROLE_NAME")
            }]
    else:
        raw = [{
            "account_id": os.getenv("CENTRAL_ADMIN_ACCOUNT_ID"),
            "role_name": os.getenv("CENTRAL_ADMIN_ROLE_NAME")
        }]

    fail_notes = []
    for mapping in raw:
        acct_id = mapping.get("account_id")
        role = mapping.get("role_name")
        print(f"Checking account {acct_id} with role {role}")
        client = get_route53_client(acct_id, role)

        try:
            found, zone_ids = check_if_domain_in_hosted_zones(dns_details, client)
            if not found:
                fail_notes.append(f"Domain '{dns_details['domain']}' not found in account {acct_id}.")
                continue
        except Exception as e:
            fail_notes.append(f"Account {acct_id} domain check => {e}")
            continue

        zone_failures = []
        for z_id in zone_ids:
            try:
                check_route53_limits(z_id, client)
            except Exception as e:
                zone_failures.append(f"zone {z_id} => limit => {e}")
                continue

            # if SPF
            if dns_details["dns_type"].upper() == "TXT" and dns_details["dns_value"].lower().startswith("v=spf1"):
                try:
                    spf_ex, spf_list = spf_record_exists_in_zone(z_id, client)
                    if spf_ex:
                        zone_failures.append(f"zone {z_id} => SPF already exists.")
                        continue
                except Exception as e:
                    zone_failures.append(f"zone {z_id} => SPF check => {e}")
                    continue

            try:
                ret = add_dns_record(dns_details, z_id, client, account_id=acct_id)
            except Exception as e:
                zone_failures.append(f"zone {z_id} add => {e}")
                continue

            if ret in ["added", "exists"]:
                # success
                success_info = {
                    "account_id": acct_id,
                    "zone_id": z_id,
                    "dns_name": dns_details["dns_name"],
                    "dns_type": dns_details["dns_type"],
                    "domain": dns_details["domain"],
                    "result": ret
                }
                return True, None, success_info
            else:
                zone_failures.append(f"zone {z_id} => {ret}")

        if zone_failures:
            fail_notes.append(f"Account {acct_id}: domain found but zones failed => " + ", ".join(zone_failures))
        else:
            fail_notes.append(f"Account {acct_id}: domain found but no zone updated => unknown")

    if fail_notes:
        combined = "\n".join(fail_notes)
        return False, f"No DNS record was added. Summary:\n{combined}", None
    else:
        return False, "No accounts matched or domain not found anywhere. Not added.", None


def prepare_public_response(dns_details, ticket_id, zendesk_agent, success_info=None):
    ticket_data = zendesk_agent.get(f"tickets/{ticket_id}")
    if ticket_data and "ticket" in ticket_data:
        req_id = ticket_data["ticket"].get("requester_id")
        user_data = zendesk_agent.get(f"users/{req_id}")
        if user_data and "user" in user_data:
            fn = user_data["user"]["name"].split()[0]
        else:
            fn = "Customer"
    else:
        fn = "Customer"

    dn = dns_details.get("dns_name", "")
    dt = dns_details.get("dns_type", "")
    dv = dns_details.get("dns_value", "")
    dom = dns_details.get("domain", "")

    extra_acct = ""
    if success_info:
        acct = success_info.get("account_id")
        zid = success_info.get("zone_id")
        if acct and zid:
            extra_acct = f"\nAWS Account: {acct}\nHosted Zone: {zid}\n"

    pub = textwrap.dedent(f"""\
        Dear {fn},

        Thank you for contacting the Central SaaS Support Team.

        We are pleased to confirm that the new DNS record has been added automatically:

        ```
        DNS Name: {dn}
        Record Type: {dt}
        Value: {dv}
        Domain: {dom}
        ```
        
        *Please note that DNS changes can take up to 24 hours (in rare cases, up to 48 hours) to propagate.*
        *Your new record might not be immediately visible in all regions.*

        Should you require further assistance, please do not hesitate to reach out.
        """).strip()

    return pub


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

    action = body.get("action")
    ticket_id = body.get("ticket_id")
    print(f"Running {action}")
    print(f"Ticket ID: {ticket_id}")

    if action and ticket_id:
        if action == "add_dns":
            zendesk_agent = zendesk_connection.ZendeskConnect()
            # remove old tags
            zendesk_agent.delete_tags(ticket_id, [START_TAG])
            zendesk_agent.add_tags(ticket_id, [WIP_TAG])

            # Retrieve the ticket to see current tags
            ticket_data = zendesk_agent.get(f"tickets/{ticket_id}")
            existing_tags = []
            if ticket_data and "ticket" in ticket_data:
                existing_tags = ticket_data["ticket"].get("tags", [])

            # If we've already done a success, skip
            if DNS_RECORD_SUCCESS_TAG in existing_tags:
                # We skip repeating the public reply
                # Just add an internal note or do nothing
                skip_note = "DNS record addition: This ticket already has dns-record-success tag. Skipping."
                print(skip_note)
                # post_internal_note_once(ticket_id, skip_note, zendesk_agent)

                # Cleanup tags
                zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
                zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])

                # optionally send a summary email if you want
                send_notification_email(
                    f"DNS Automation (Ticket {ticket_id})",
                    f"Already success => skipping second run for {ticket_id}."
                )
                return {
                    "statusCode": 200,
                    "body": json.dumps({"message": f"{action} is completed (skipped)."})
                }

            description = body.get("description", "")
            if not description:
                success = False
                internal_note = "No description found."
                success_info = None
            else:
                success, internal_note, success_info = process_dns_request(description)

            # cleanup
            zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
            zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])

            if success:
                # success => add public reply once
                zendesk_agent.add_tags(ticket_id, [ATLAS_CUSTOM_CLOSURE_TAG, DNS_RECORD_SUCCESS_TAG])
                dns_details = extract_dns_details(description)
                public_msg = prepare_public_response(dns_details, ticket_id, zendesk_agent, success_info)
                zendesk_agent.send_to_customer_macro(ticket_id, public_msg)
            else:
                # failure => internal note
                if internal_note:
                    post_internal_note_once(ticket_id, internal_note, zendesk_agent)
                else:
                    post_internal_note_once(ticket_id, "DNS automation failed with no detail.", zendesk_agent)

                # If domain not found => place on hold (once)
                if "not found" in (internal_note.lower()):
                    current_ticket = zendesk_agent.get(f"tickets/{ticket_id}")
                    if current_ticket and "ticket" in current_ticket:
                        status = current_ticket["ticket"].get("status", "").lower()
                        tags = current_ticket["ticket"].get("tags", [])
                        if status != "hold" and HOLD_TAG not in tags:
                            zendesk_agent.send_to_external_team_macro(
                                ticket_id,
                                reason="Automation adding necessary permissions",
                                offset=24,
                                external_team="team_internal",
                                escalation_target="tempo_other"
                            )
                            zendesk_agent.add_tags(ticket_id, [HOLD_TAG])
                        else:
                            print("Ticket already on hold or hold-tag found; skipping second hold.")

            # summary email
            sub = f"DNS Automation Summary for Ticket {ticket_id}"
            if success:
                ebody = f"Ticket {ticket_id} => SUCCESS.\n{success_info or 'Record added/exists'}"
            else:
                ebody = f"Ticket {ticket_id} => FAIL.\n{internal_note or 'No detail'}"
            send_notification_email(sub, ebody)

        elif action == "add_dns_need_sc":
            sc_approval_scenario.send_for_approval(body, ticket_id)

        elif action == "add_dns_sc_received":
            is_approved = sc_approval_scenario.evaluate_approval(ticket_id)
            zendesk_agent = zendesk_connection.ZendeskConnect()
            zendesk_agent.delete_tags(ticket_id, [START_TAG, WIP_TAG])
            zendesk_agent.add_tags(ticket_id, [COMPLETED_TAG])
            if is_approved:
                zendesk_agent.add_tags(ticket_id, [ATLAS_CUSTOM_CLOSURE_TAG])
                msg = "Your DNS request is approved and completed"
                zendesk_agent.send_to_customer_macro(ticket_id, msg)
            else:
                post_internal_note_once(ticket_id, "DNS request not approved, stopping.", zendesk_agent)
        else:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": f"Unsupported action: {action}"})
            }

        return {
            "statusCode": 200,
            "body": json.dumps({"message": f"{action} is completed."})
        }
    else:
        return {
            "statusCode": 404,
            "body": json.dumps({"message": "ERROR: missing ticket_id or action"})
        }


def load_parameters(name):
    ssm = boto3.client("ssm", region_name="us-east-1")
    resp = ssm.get_parameter(Name=name, WithDecryption=True)
    return json.loads(resp["Parameter"]["Value"])


if __name__ == "__main__":
    sample_event = {
        "action": "add_dns",
        "ticket_id": "1234567",
        "description": "DNS Name: test\ndomain: example.com\nDNS Type: A\nDNS Value: 1.2.3.4"
    }
    lambda_handler(sample_event, None)
