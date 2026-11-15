data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/src/remediate_key.py"
  output_path = "${path.module}/remediate_key.zip"
}

resource "aws_lambda_function" "key_remediator" {
  function_name                  = "iam-access-key-remediator-${var.environment}"
  role                           = aws_iam_role.lambda_exec_role.arn
  handler                        = "remediate_key.lambda_handler"
  runtime                        = "python3.12"
  filename                       = data.archive_file.lambda_zip.output_path
  source_code_hash               = data.archive_file.lambda_zip.output_base64sha256
  timeout                        = 15
  memory_size                    = 128
  reserved_concurrent_executions = 10
  kms_key_arn                    = aws_kms_key.secops_cmk.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.remediation_dlq.arn
  }

  environment {
    variables = {
      EXEMPT_USERS  = join(",", var.exempt_users)
      SNS_TOPIC_ARN = aws_sns_topic.secops_alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda_logs]
}

# EventBridge Rule matching CloudTrail CreateAccessKey API calls
resource "aws_cloudwatch_event_rule" "detect_create_access_key" {
  name        = "detect-iam-create-access-key-${var.environment}"
  description = "Intercepts IAM CreateAccessKey management events via CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateAccessKey"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.detect_create_access_key.name
  target_id = "IAMKeyRemediatorLambda"
  arn       = aws_lambda_function.key_remediator.arn

  dead_letter_config {
    arn = aws_sqs_queue.remediation_dlq.arn
  }

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.key_remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detect_create_access_key.arn
}