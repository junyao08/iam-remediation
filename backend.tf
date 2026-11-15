terraform {
  required_version = ">=1.10.0"

  required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "~> 6.0"
    }

    archive = {
        source = "hashicorp/archive"
        version = "~> 2.7"
    }
  }

  # Production backend (overridden locally by override.tf for Floci)
  backend "s3" {
    bucket = "org-secops-tfstate-prod-us-east-1"
    key = "secops/iam-key-remediation/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    kms_key_id = "alias/terraform-state-key"
    use_lockfile = true
  }
}