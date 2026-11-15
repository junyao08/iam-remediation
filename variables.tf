variable "aws_region" {
    description = "AWS control-plan region (IAM global events emit exclusively in us-east-1)"
    type = string
    default = "us-east-1"

    validation {
      condition = var.aws_region == "us-east-1"
      error_message = "Global IAM CloudTrail events are emitte exclusively in us-east-1"
    }
}

variable "environment" {
  description = "Deployment environment label (lab, staging, prod)"
  type = string
  default = "junlab"
}

variable "exempt_users" {
  description = "VIP IAM usernames allowed to keep access keys"
  type = list(string)
  default = [ "breakglass-admin" ] #breakglass is an emergency account
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch forensic logs"
  type = number
  default = 365
}