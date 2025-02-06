[Add/Edit DNS Record Documentation](https://trilogy-confluence.atlassian.net/wiki/spaces/SAASOPS/pages/901152938/Add+Edit+DNS+Record)

## Add DNS Automation

This repository hosts an AWS Lambda function named **add_dns**, triggered by Zendesk tickets to automatically add DNS records in Route53. It is based on the [CSAI Lambda Automation Boilerplate](https://github.com/trilogy-group/csai-lambda-automation-boilerplate) but has been tailored for our **Central Admin** DNS workflow with extended multi-account support and API throttling protection.

## Table of Contents

- [Overview](#overview)
- [Key Files](#key-files)
- [Validation Flow](#validation-flow)
- [Cross-Account Permissions](#cross-account-permissions)
- [Deployment](#deployment)
- [Usage](#usage)
- [Expanding Functionality to Other Accounts](#expanding-functionality-to-other-accounts)
- [References](#references)

---

## Overview

1. **Zendesk Trigger & Webhook**  
    A Zendesk trigger looks for a specific tag (`add_dns-trigger`) and posts JSON to an API Gateway endpoint linked to this Lambda function.
    
2. **Lambda (`app.py`)**  
    The Lambda code:
    
    - Parses the DNS record details from the ticket’s `description`.
    - Validates the record (e.g., domain format, DNS type, IP address, etc.).
    - Assumes cross-account IAM roles (using the environment variable `DNS_ACCOUNT_ROLE_MAPPINGS`) to create the record via Route53. It first tries the central admin account, then additional accounts (e.g., Contently Prod), if needed.
    - Wraps Route53 API calls with exponential backoff to mitigate throttling errors.
    - Sends a public reply to the ticket (via Zendesk’s macro), which—according to your Zendesk configuration—sets the ticket to **pending**.
3. **Route53**  
    Hosted zones may reside in multiple accounts. The function assumes the appropriate IAM role (e.g., `CentralAdminDNSManager` or `DNSManager`) based on your environment variable settings to update DNS records.
    

---

## Key Files

- **`app.py`**  
    Main entry point. Contains:
    
    - `lambda_handler`: Orchestrates the workflow from Zendesk payload to DNS creation and ticket response.
    - `process_dns_request`: Implements the core logic for domain verification, validation, and record creation across multiple AWS accounts.
    - `prepare_public_response`: Formats the public reply sent back to Zendesk.
    - `call_api`: A helper function that wraps Route53 API calls with exponential backoff to handle throttling.
- **`zendesk_connection.py`**  
    A wrapper for Zendesk interactions:
    
    - `send_to_customer_macro`: Posts a public comment and (via Zendesk macros) sets the ticket status to **pending**.
    - `write_internal_note`: Adds an internal note.
    - `add_tags` / `delete_tags`: Manages ticket tags for tracking.
- **`sc_approval_scenario.py`**  
    (Optional) Provides an example for handling side-conversation approvals.
    
- **`openai_ops.py`**  
    (Optional) Shows how to integrate with OpenAI for advanced logic.
    

---

## Validation Flow

The function **`validate_dns_details(dns_details)`** performs several checks:

- **Domain & DNS Name Format:** Ensures both are valid (supports IDNs).
- **Wildcard and Apex Restrictions:** Validates wildcard records and prevents adding a CNAME at the apex.
- **Type-Specific Validation:** Checks for proper formats for record types (A, AAAA, MX, TXT, etc.).
- **Hosted Zone Existence:** The function **`check_if_domain_in_hosted_zones`** verifies that the domain exists in the target account’s Route53 hosted zones.

If any validation fails, an internal note is added to the ticket and no DNS record is created.

---

## Cross-Account Permissions

The Lambda function now supports multiple accounts using the environment variable **`DNS_ACCOUNT_ROLE_MAPPINGS`**. For example:

`[   { "account_id": "646253092271", "role_name": "CentralAdminDNSManager" },   { "account_id": "727712672144", "role_name": "DNSManager" } ]`

**Key Points:**

- The function attempts the central admin account first (ID: 646253092271), then the Contently Prod account (ID: 727712672144), and so on.
- The Lambda execution role must be allowed to assume these roles (via an IAM policy).
- Each target role must trust the Lambda execution role in its trust policy.
- The helper function `call_api` is used to handle API throttling by retrying with exponential backoff.

---

## Deployment

### Prerequisites

- AWS SAM (or an equivalent deployment tool).
- Correct environment variables configured (e.g., `CENTRAL_ADMIN_ACCOUNT_ID`, `CENTRAL_ADMIN_ROLE_NAME`, and `DNS_ACCOUNT_ROLE_MAPPINGS`).
- IAM permissions for deployment in your Lambda’s account.

### Deployment Steps (SAM Example)

1. Clone or copy the repository locally.
2. (Optional) Run `pip install -r requirements.txt` to install dependencies.
3. Execute `sam build` to build the project.
4. Run `sam deploy --guided` to deploy the Lambda function.
5. After deployment, verify the environment variables in the Lambda console.

---

## Usage

1. **Zendesk Trigger:**  
    Tag a ticket with `add_dns-trigger`. This sends a JSON payload (including fields like `action`, `ticket_id`, and `description`) to the API Gateway endpoint.
    
    **Example Payload:**

    `{   "action": "add_dns",   "ticket_id": "123456",   "description": "DNS Name: test\nDomain: example.com\nDNS Type: A\nDNS Value: 1.2.3.4" }`
    
2. **Lambda Execution:**
    
    - The Lambda function parses and validates the DNS record.
    - It then checks for the domain in each configured account and attempts to create the record via Route53.
    - If successful, it calls the Zendesk macro (`send_to_customer_macro`), which sends a public reply and sets the ticket to **pending**.
    - If any validations fail, the function writes an internal note.
3. **Failure Handling:**
    
    - Detailed failure messages are recorded if the DNS record cannot be added.

---

## Expanding Functionality to Other Accounts

No code changes are needed. **Three steps** are required to add a new account:

1. **Create the IAM Role in the Target Account:**
    
    - In the target account, got to IAM --> Roles and create an IAM role (`DNSManager`)
    - Set the trusted entity type to **AWS account**, choose "Another AWS account" and specify Lambda’s account ID (899084202472). Click "Next"
    - Add permission `AmazonRoute53FullAccess` and click "Next"
    - Name Role "DNSManager" and click "Create Role"
    - After creating the role, edit the trust relationship > trust policy to:
      

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::899084202472:user/janp"
            },
            "Action": "sts:AssumeRole"
        },
        {
            "Sid": "AllowLambdaExecutionRole",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::899084202472:role/add-dns-AddDnsFunctionRole-VhfqUK6mRbe9"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

2. **Update `DNS_ACCOUNT_ROLE_MAPPINGS`:** in  RAM-AWS-CoreSupport-Admin (899084202472)

    
    - Navigate to Lambda --> Functions --> add_dns --> Configuration tab --> Environment variables
    - Click Edit and find the DNS_ACCOUNT_ROLE_MAPPINGS key
    - Append a new JSON object for the target account to the array. For example:
      
        
        `[   { "account_id": "646253092271", "role_name": "CentralAdminDNSManager" },   { "account_id": "727712672144", "role_name": "DNSManager" },   { "account_id": "XXXXXXXXXXXX", "role_name": "NewTargetRole" } ]`
        

3. **Modify IAM Role add-dns-AddDnsFunctionRole-VhfqUK6mRbe9 in CoreSupport-Admin**

Just add a new policy. You can name the policy with the target account ID or its name
    - Still in CoreSupport-Admin (AWS account ID 899084202472) navigate to IAM --> Roles
    - Find `add-dns-AddDnsFunctionRole-VhfqUK6mRbe9` Role
    - Click Add permissions --> Create inline policy
    - Choose JSON and in the policy editor write:
    
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:I am::<<new_AWS_account_id>>:role/<<role_name>>"
        }
    ]
}
```
Example:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::600506650469:role/DNSManager"
        }
    ]
}
```

**If AWS Account ID starts with a zero (0) digit, make sure to include this leading zero**

---

## References

- [CSAI Lambda Automation Boilerplate](https://github.com/trilogy-group/csai-lambda-automation-boilerplate)
- [AWS Route53 Documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html)
- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
- [Zendesk Developer Docs](https://developer.zendesk.com/documentation/))

**Maintainer**: `[CS / Jan Paraniak]`  
**Contact**: `jan.paraniak@trilogy.com` (for questions/bug reports)

---

This README now reflects the latest functionality—supporting multi-account DNS updates with API throttling protection while preserving the original Zendesk integration behavior.
