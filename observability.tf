# 1. Encrypted CloudWatch Log Group for Lambda forensics
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/iam-access-key-remediator-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.secops_cmk.arn
}

# 2. Encrypted SNS Topic for SecOps Real-Time Alerting
resource "aws_sns_topic" "secops_alerts" {
  name              = "secops-iam-key-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.secops_cmk.id
}

# 3. Encrypted SQS Dead-Letter Queue (captures failed EventBridge/Lambda deliveries)
resource "aws_sqs_queue" "remediation_dlq" {
  name                      = "secops-iam-key-remediation-dlq-${var.environment}"
  kms_master_key_id         = aws_kms_key.secops_cmk.id
  message_retention_seconds = 1209600 # 14 days
}