terraform {
  backend "s3" {
    bucket         = "famsbh-terraform-bucket"
    key            = "state/kms.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}
