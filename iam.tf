# 1. IAM Permission Boundary (hard guardrail capping maximum privileges)
resource "aws_iam_policy" "lambda_boundary" {
  name        = "secops-iam-remediator-boundary-${var.environment}"
  description = "Permission boundary restricting Lambda strictly to key deactivation, telemetry, and DLQ"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowScopedIAMKeyContainment"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      {
        Sid    = "AllowTelemetryAndDLQ"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "sns:Publish",
          "sqs:SendMessage",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_cloudwatch_log_group.lambda_logs.arn,
          "${aws_cloudwatch_log_group.lambda_logs.arn}:*",
          aws_sns_topic.secops_alerts.arn,
          aws_sqs_queue.remediation_dlq.arn,
          aws_kms_key.secops_cmk.arn
        ]
      }
    ]
  })
}

# 2. Lambda Execution Role with Permission Boundary Attached
resource "aws_iam_role" "lambda_exec_role" {
  name                 = "secops-iam-remediator-role-${var.environment}"
  permissions_boundary = aws_iam_policy.lambda_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# 3. Least-Privilege Execution Policy (Zero "*" resources)
resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "secops-iam-remediator-policy"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DeactivateNonExemptAccessKeys"
        Effect   = "Allow"
        Action   = ["iam:UpdateAccessKey", "iam:ListAccessKeys"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      {
        Sid      = "WriteForensicLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      },
      {
        Sid      = "PublishSecOpsAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.secops_alerts.arn
      },
      {
        Sid      = "SendFailedEventsToDLQ"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.remediation_dlq.arn
      },
      {
        Sid      = "UseCMKForEnvAndTelemetry"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.secops_cmk.arn
      }
    ]
  })
}