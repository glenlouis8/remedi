# =============================================================================
# REMEDI TEST ENVIRONMENT — DELIBERATELY VULNERABLE
# =============================================================================
# This file creates an AWS environment with one known vulnerability per service
# so you can verify Remedi detects and remediates each one correctly.
#
# DO NOT deploy this in a production account.
#
# COST ESTIMATE: ~$0.05/hr while running (RDS t3.micro is the main cost).
# Run `terraform destroy` when done testing.
#
# DEPLOY:
#   terraform init
#   terraform apply
#
# CLEAN UP:
#   terraform destroy
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}

# =============================================================================
# NETWORKING
# =============================================================================

# VPC — flow logs intentionally disabled (triggers VPC finding)
resource "aws_vpc" "test" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = { Name = "remedi-test-vpc" }
}

resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags   = { Name = "remedi-test-igw" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.test.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags                    = { Name = "remedi-test-subnet-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.test.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.region}b"
  tags              = { Name = "remedi-test-subnet-b" }
}

# =============================================================================
# SECURITY GROUP — triggers Security Group finding
# Port 22 (SSH) and port 80 open to 0.0.0.0/0
# =============================================================================

resource "aws_security_group" "vulnerable" {
  name        = "remedi-test-open-sg"
  description = "Deliberately open security group for Remedi testing"
  vpc_id      = aws_vpc.test.id

  # VULNERABILITY: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: HTTP open to the world
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "remedi-test-open-sg" }
}

# =============================================================================
# EC2 — triggers EC2 finding
# IMDSv1 enabled (http_tokens = "optional" instead of "required")
# =============================================================================

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "vulnerable" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.vulnerable.id]

  # VULNERABILITY: IMDSv1 enabled
  metadata_options {
    http_tokens = "optional"
  }

  tags = { Name = "remedi-test-ec2" }
}

# =============================================================================
# S3 — triggers S3 finding
# Public access block disabled + bucket policy allows public reads
# =============================================================================

resource "aws_s3_bucket" "vulnerable" {
  bucket        = "remedi-test-public-bucket-${random_id.suffix.hex}"
  force_destroy = true
  tags          = { Name = "remedi-test-public-bucket" }
}

resource "random_id" "suffix" {
  byte_length = 4
}

# VULNERABILITY: Disables all public access blocks
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABILITY: Allows anyone to read objects
resource "aws_s3_bucket_policy" "vulnerable" {
  bucket     = aws_s3_bucket.vulnerable.id
  depends_on = [aws_s3_bucket_public_access_block.vulnerable]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.vulnerable.arn}/*"
    }]
  })
}

# =============================================================================
# IAM — triggers IAM finding
# A user with AdministratorAccess directly attached
# =============================================================================

resource "aws_iam_user" "vulnerable" {
  name = "remedi-test-admin-user"
  tags = { Purpose = "Remedi testing - delete after use" }
}

resource "aws_iam_user_policy_attachment" "admin" {
  user       = aws_iam_user.vulnerable.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# RDS — triggers RDS finding
# PostgreSQL instance with publicly_accessible = true
# =============================================================================

resource "aws_db_subnet_group" "test" {
  name       = "remedi-test-db-subnet-group"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags       = { Name = "remedi-test-db-subnet-group" }
}

resource "aws_db_instance" "vulnerable" {
  identifier        = "remedi-test-db"
  engine            = "postgres"
  engine_version    = "15"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "testdb"
  username = "testadmin"
  password = "TestPassword123!"

  db_subnet_group_name   = aws_db_subnet_group.test.name
  vpc_security_group_ids = [aws_security_group.vulnerable.id]

  # VULNERABILITY: Publicly accessible database
  publicly_accessible = true

  skip_final_snapshot = true
  tags                = { Name = "remedi-test-db" }
}

# =============================================================================
# LAMBDA — triggers Lambda finding
# Function with an AdministratorAccess execution role
# =============================================================================

resource "aws_iam_role" "lambda_vulnerable" {
  name = "remedi-test-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# VULNERABILITY: Lambda execution role has full admin access
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_vulnerable.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "vulnerable" {
  function_name = "remedi-test-lambda"
  role          = aws_iam_role.lambda_vulnerable.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = data.archive_file.lambda_zip.output_path

  tags = { Name = "remedi-test-lambda" }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "/tmp/remedi_test_lambda.zip"

  source {
    content  = "exports.handler = async () => ({ statusCode: 200, body: 'ok' });"
    filename = "index.js"
  }
}

# =============================================================================
# CLOUDTRAIL — triggers CloudTrail finding
# No trail is created. The absence of a trail IS the vulnerability.
# If you previously ran `remediate_cloudtrail`, delete that trail first.
# =============================================================================

# =============================================================================
# OUTPUTS
# =============================================================================

output "vpc_id" {
  value = aws_vpc.test.id
}

output "security_group_id" {
  value = aws_security_group.vulnerable.id
}

output "ec2_instance_id" {
  value = aws_instance.vulnerable.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.vulnerable.bucket
}

output "iam_test_user" {
  value = aws_iam_user.vulnerable.name
}

output "rds_identifier" {
  value = aws_db_instance.vulnerable.identifier
}

output "lambda_function_name" {
  value = aws_lambda_function.vulnerable.function_name
}

output "summary" {
  value = <<-EOT
    Remedi Test Environment deployed.
    Expected findings:
      IAM          — remedi-test-admin-user has AdministratorAccess
      S3           — ${aws_s3_bucket.vulnerable.bucket} is publicly readable
      VPC          — ${aws_vpc.test.id} has flow logs disabled
      Sec Groups   — ${aws_security_group.vulnerable.id} open on 22 + 80
      EC2          — ${aws_instance.vulnerable.id} has IMDSv1 enabled
      RDS          — remedi-test-db is publicly accessible
      Lambda       — remedi-test-lambda has AdministratorAccess role
      CloudTrail   — no trails exist
  EOT
}
