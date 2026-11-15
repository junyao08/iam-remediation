terraform {
  # Store state on local disk, testing in floci
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = "us-east-1"
  access_key = "test" # Dummy key for floci
  secret_key = "test" #
  skip_credentials_validation = true # Don't ask real AWS to validate "test" keys
  skip_metadata_api_check = true # Don't look for real EC2 metadata servers
  skip_requesting_account_id = true

  # Route all AWS API calls to floci docker container
  endpoints {
    cloudwatch = "http://localhost:4566"
    cloudwatchlogs = "http://localhost:4566"
    events  = "http://localhost:4566"
    iam = "http://localhost:4566"
    kms = "http://localhost:4566"
    lambda = "http://localhost:4566"
    sns = "http://localhost:4566"
    sqs = "http://localhost:4566"
    sts = "http://localhost:4566"

  }
}