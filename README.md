cat << 'EOF' > README.md
# Automated IAM Access Key Remediation on AWS

![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.10.0-623CE4?style=flat-square&logo=terraform&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20EventBridge%20%7C%20Lambda-232F3E?style=flat-square&logo=amazonwebservices&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-CIS%20v3.0%20%7C%20NIST%20800--53%20%7C%20CSA%20CCM%20v4.1-0F766E?style=flat-square)

Event-driven cloud security control that intercepts `iam:CreateAccessKey` API calls via CloudTrail and EventBridge, automatically revoking unauthorized static IAM access keys in under 5 seconds while preserving approved break-glass identities[cite: 5, 7].

---

## Architecture

![Automated IAM Access Key Remediation Architecture](./architecture.png)

### How It Works

1. **Detection (`CloudTrail` + `EventBridge`):** CloudTrail logs `CreateAccessKey` management events in `us-east-1` and routes matching events to EventBridge in near real time[cite: 7].
2. **Evaluation (`AWS Lambda`):** `remediate_key.py` parses the event payload and checks the target user against the `EXEMPT_USERS` allowlist[cite: 5, 7].
   * **Non-Exempt User:** Immediately calls `iam:UpdateAccessKey` to set the key status to `Inactive`.
   * **Exempt User (`breakglass-admin`):** Leaves the key `Active` and logs a medium-severity audit event.
3. **Resilience & Telemetry (`SQS DLQ`, `SNS`, `CloudWatch`, `KMS`):** Failed deliveries route to an encrypted SQS Dead-Letter Queue (14-day retention), while all audit logs, alerts, and environment variables are encrypted with a rotating KMS Customer Managed Key.

---

## Quick Start (Local Floci Emulator)

### Prerequisites

* Docker Engine / Docker Desktop
* Terraform `>= 1.10.0`
* AWS CLI v2

### 1. Start Local AWS Emulator

```bash
docker compose up -d
