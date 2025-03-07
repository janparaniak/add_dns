[Add DNS Record Documentation](https://trilogy-confluence.atlassian.net/wiki/spaces/SAASOPS/pages/901152938/Add+Edit+DNS+Record)

## Add DNS Automation

This repository hosts an AWS Lambda function named **`add_dns`**, which is triggered by Zendesk tickets to automatically add DNS records in Amazon Route 53. It originated from the [CSAI Lambda Automation Boilerplate](https://github.com/trilogy-group/csai-lambda-automation-boilerplate) and has been enhanced for multi-account support, robust validation, and API throttling protection, specifically tailored to our **Central Admin** DNS workflow.

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
   The Lambda:
   - Extracts DNS record details from a ticket’s `description`.
   - Validates the data (domain format, DNS type, etc.).
   - Assumes cross-account IAM roles to create records in Route 53. The roles and account IDs are managed via the `DNS_ACCOUNT_ROLE_MAPPINGS` environment variable.
   - Uses exponential backoff (`call_api`) to mitigate throttling errors from Route 53.
   - Sends a public reply on Zendesk (via a macro), which typically sets the ticket to **pending**.

3. **Route 53**  
   Hosted zones may be scattered across multiple AWS accounts. The function attempts updates in each relevant account (e.g., Central Admin, Contently Prod), stopping when a match is found.

---

## Key Files

1. **`app.py`**  
   Main entry point. Contains:
   - **`lambda_handler`**: Orchestrates the workflow from the incoming Zendesk payload to DNS creation and final ticket updates.  
   - **`process_dns_request`**: Handles domain checks, validation, and tries each account for Route 53 updates.  
   - **`prepare_public_response`**: Builds the public reply posted back to Zendesk.  
   - **`call_api`**: Wraps AWS Route 53 API calls with retry logic to handle throttling.  

2. **`zendesk_connection.py`**  
   Contains helper methods for interacting with Zendesk:
   - `send_to_customer_macro` (public replies + macros)  
   - `write_internal_note`  
   - `add_tags` / `delete_tags`  

3. **`sc_approval_scenario.py`**  
   (Optional) Demonstrates how side-conversation approvals can be integrated if needed.

4. **`openai_ops.py`**  
   (Optional) Illustrates how you could incorporate OpenAI-based logic. Not strictly required for DNS.

---

## Validation Flow

Within **`process_dns_request()`**, your code first calls **`validate_dns_details()`**:

- **Domain & DNS Name Format**: Ensures validity (including IDN support).  
- **Apex Restrictions**: Prevents adding a CNAME at the apex if `dns_name` is blank.  
- **Type-Specific Checks**: Ensures data is consistent with the record type (A, TXT, MX, etc.).  
- **Hosted Zone Lookups**: Uses **`check_if_domain_in_hosted_zones()`** to confirm that the domain is managed in a given account’s Route 53.

If any check fails, the Lambda posts an internal note in the ticket detailing the error, and no DNS record is created.

---

## Cross-Account Permissions

The Lambda can update DNS across multiple AWS accounts based on **`DNS_ACCOUNT_ROLE_MAPPINGS`**. For example:

```json
[
  { "account_id": "646253092271", "role_name": "CentralAdminDNSManager" },
  { "account_id": "727712672144", "role_name": "DNSManager" }
]
```

**Important Points**:

- The Lambda execution role must have permission to **assume** these roles.  
- Each target role must trust the Lambda’s execution role in its trust policy.  
- The function tries the first account in the list (e.g., Central Admin), then subsequent accounts until the correct hosted zone is found.

---

## Deployment

### Prerequisites

- AWS SAM or another deployment tool.  
- Valid environment variables:  
  - `CENTRAL_ADMIN_ACCOUNT_ID`  
  - `CENTRAL_ADMIN_ROLE_NAME`  
  - `DNS_ACCOUNT_ROLE_MAPPINGS`  
- IAM permissions for your deployment user or role.

### Steps (with SAM)

1. **Clone** or copy this repo locally.  
2. Optionally, run `pip install -r requirements.txt` to install dependencies if you’re testing locally.  
3. `sam build` to build the Lambda.  
4. `sam deploy --guided` to deploy.  
5. Configure environment variables (like `DNS_ACCOUNT_ROLE_MAPPINGS`) in the Lambda console or your SAM template.

---

## Usage

1. **Ticket Creation & Tagging**  
   A Zendesk trigger adds the tag `add_dns-trigger`. This fires a webhook to API Gateway with JSON data, e.g.:

   ```json
   {
     "action": "add_dns",
     "ticket_id": "1234567",
     "description": "DNS Name: foo\ndomain: example.com\nDNS Type: A\nDNS Value: 1.2.3.4"
   }
   ```

2. **DNS Handling**  
   The Lambda reads `description`, extracts DNS details, and attempts record creation in each account’s Route 53. If successful, it responds publicly on the ticket.

3. **Failure**  
   If no DNS record can be created or validation fails, an internal note is posted explaining the reason.

---

## Expanding Functionality to Other Accounts

To include a new AWS account, **no code changes** are necessary. You only need to:

1. **Create the IAM Role** in that account (e.g., `DNSManager`) with `AmazonRoute53FullAccess`, trusting the Lambda’s execution role.  
2. **Update** the environment variable **`DNS_ACCOUNT_ROLE_MAPPINGS`** to add a JSON object for the new account.  
3. **Grant** the Lambda’s role permission to `sts:AssumeRole` on the new `DNSManager` role in the target account.

Once these steps are complete, the function can assume the new role and attempt DNS updates in that account automatically.

---

## References

- [CSAI Lambda Automation Boilerplate](https://github.com/trilogy-group/csai-lambda-automation-boilerplate)  
- [AWS Route 53 Documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html)  
- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)  
- [Zendesk Developer Docs](https://developer.zendesk.com/documentation/)

**Maintainer**: `[CS / Jan Paraniak]`  
**Contact**: `jan.paraniak@trilogy.com` (for questions/bug reports)

---

*This README describes how the Lambda automatically handles DNS updates across multiple AWS accounts with minimal manual intervention.*
