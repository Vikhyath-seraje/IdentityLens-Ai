locals {
  # Add a random suffix to ensure globally unique bucket names
  random_suffix = random_string.suffix.result
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "aws_s3_bucket" "customer_data" {
  bucket = "${var.project_name}-customer-data-${local.random_suffix}"
  tags = {
    Name        = "Customer Data"
    Environment = "Hackathon"
  }
}

resource "aws_s3_bucket" "financial_records" {
  bucket = "${var.project_name}-financial-records-${local.random_suffix}"
  tags = {
    Name        = "Financial Records"
    Environment = "Hackathon"
  }
}

resource "aws_s3_bucket" "internal_backups" {
  bucket = "${var.project_name}-internal-backups-${local.random_suffix}"
  tags = {
    Name        = "Internal Backups"
    Environment = "Hackathon"
  }
}

# Block public access for these sensitive buckets
resource "aws_s3_bucket_public_access_block" "customer_data_block" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "financial_records_block" {
  bucket                  = aws_s3_bucket.financial_records.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "internal_backups_block" {
  bucket                  = aws_s3_bucket.internal_backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Fetch the latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "prod_server" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  tags = {
    Name        = "${var.project_name}-prod-server"
    Environment = "Hackathon"
  }
}
