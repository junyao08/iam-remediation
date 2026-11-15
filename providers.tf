provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project = "IAM-AccessKey-Remediation"
      Environment = var.environment
      ManagedBy = "Terraform"
      Compliance = "CIS-v3-NIST-800-53-CSA-CCM-v4.1"
    }
  }
}