output "lambda_function_arn" {
  description = "ARN of the IAM Access Key Remediator Lambda"
  value       = aws_lambda_function.key_remediator.arn
}

output "sns_topic_arn" {
  description = "ARN of the encrypted SecOps SNS alert topic"
  value       = aws_sns_topic.secops_alerts.arn
}

output "dlq_url" {
  description = "URL of the SQS Dead-Letter Queue"
  value       = aws_sqs_queue.remediation_dlq.id
}

output "kms_key_arn" {
  description = "ARN of the SecOps Customer Managed Key"
  value       = aws_kms_key.secops_cmk.arn
}