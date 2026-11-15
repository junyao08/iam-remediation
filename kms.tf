# Get my AWS Acccount ID, in floci will be 0000000000 (12-digit)
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "secops_cmk" {
  description = "CMK for IAM key remediation telemetry, DLQ and Lambda env encryption"
  deletion_window_in_days = 30
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Sid = "EnableRootAccountPermissions"
            Effect = "Allow"
            Principal = {
                AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
            }
            Action = "kms:*"
            Resource = "*"
        },
        {
            Sid = "AllowCloudWatchLogsAndEventsEncryption"
            Effect = "Allow"
            Principal = {
                Service = [
                    "logs.${var.aws_region}.amazonaws.com",
                    "events.amazonaws.com",
                    "sns.amazonaws.com"
                ]
            }
            Action = [
                "kms:Encrypt*",
                "kms:Decrypt*",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey",
                "kms:Describe*"
            ]
            Resource = "*"
        }
    ]
  })
}

resource "aws_kms_alias" "secops_cmk_alias" {
  name = "alias/secops-iam-remediation-${var.environment}"
  target_key_id = aws_kms_key.secops_cmk.key_id
}