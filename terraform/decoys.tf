# =============================================================================
# DECOYS — healthy resources with scary names, used by evals/detection_eval.py
# to measure false alarms. Off by default; deploy with:
#   terraform apply -var deploy_decoys=true
# Remedi should flag NONE of these.
# =============================================================================

variable "deploy_decoys" {
  type    = bool
  default = false
}

# S3 — name says "public", but all public access is blocked
resource "aws_s3_bucket" "decoy" {
  count         = var.deploy_decoys ? 1 : 0
  bucket        = "remedi-decoy-public-assets-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "decoy" {
  count                   = var.deploy_decoys ? 1 : 0
  bucket                  = aws_s3_bucket.decoy[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM — name says "admin", but only ReadOnlyAccess
resource "aws_iam_user" "decoy" {
  count = var.deploy_decoys ? 1 : 0
  name  = "remedi-decoy-admin"
}

resource "aws_iam_user_policy_attachment" "decoy" {
  count      = var.deploy_decoys ? 1 : 0
  user       = aws_iam_user.decoy[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Security group — HTTPS from inside the VPC only
resource "aws_security_group" "decoy" {
  count       = var.deploy_decoys ? 1 : 0
  name        = "remedi-decoy-restricted-sg"
  description = "Decoy: HTTPS from inside the VPC only"
  vpc_id      = aws_vpc.test.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

# EC2 — IMDSv2 required, encrypted root volume
resource "aws_instance" "decoy" {
  count                  = var.deploy_decoys ? 1 : 0
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.decoy[0].id]

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "remedi-decoy-ec2" }
}

# RDS — name says "public", but publicly_accessible = false
resource "aws_db_instance" "decoy" {
  count             = var.deploy_decoys ? 1 : 0
  identifier        = "remedi-decoy-public-replica"
  engine            = "postgres"
  engine_version    = "15"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "decoydb"
  username = "decoyadmin"
  password = "DecoyPassword123!"

  db_subnet_group_name   = aws_db_subnet_group.test.name
  vpc_security_group_ids = [aws_security_group.decoy[0].id]

  publicly_accessible = false
  skip_final_snapshot = true
  tags                = { Name = "remedi-decoy-public-replica" }
}

# Lambda — name says "admin", but role is basic-execution only
resource "aws_iam_role" "lambda_decoy" {
  count = var.deploy_decoys ? 1 : 0
  name  = "remedi-decoy-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_decoy" {
  count      = var.deploy_decoys ? 1 : 0
  role       = aws_iam_role.lambda_decoy[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "decoy" {
  count         = var.deploy_decoys ? 1 : 0
  function_name = "remedi-decoy-admin-tools"
  role          = aws_iam_role.lambda_decoy[0].arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = data.archive_file.lambda_zip.output_path

  tags = { Name = "remedi-decoy-admin-tools" }
}

# VPC — flow logs ENABLED
resource "aws_vpc" "decoy" {
  count      = var.deploy_decoys ? 1 : 0
  cidr_block = "10.1.0.0/16"
  tags       = { Name = "remedi-decoy-vpc" }
}

resource "aws_cloudwatch_log_group" "decoy_flow" {
  count             = var.deploy_decoys ? 1 : 0
  name              = "/remedi-decoy/vpc-flow-logs"
  retention_in_days = 1
}

resource "aws_iam_role" "decoy_flow" {
  count = var.deploy_decoys ? 1 : 0
  name  = "remedi-decoy-flowlog-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "decoy_flow" {
  count = var.deploy_decoys ? 1 : 0
  name  = "flowlog-write"
  role  = aws_iam_role.decoy_flow[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "decoy" {
  count                = var.deploy_decoys ? 1 : 0
  vpc_id               = aws_vpc.decoy[0].id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.decoy_flow[0].arn
  iam_role_arn         = aws_iam_role.decoy_flow[0].arn
}

output "decoy_ids" {
  value = var.deploy_decoys ? {
    bucket   = aws_s3_bucket.decoy[0].bucket
    iam_user = aws_iam_user.decoy[0].name
    sg_id    = aws_security_group.decoy[0].id
    ec2_id   = aws_instance.decoy[0].id
    rds_id   = aws_db_instance.decoy[0].identifier
    lambda   = aws_lambda_function.decoy[0].function_name
    vpc_id   = aws_vpc.decoy[0].id
  } : {}
}
