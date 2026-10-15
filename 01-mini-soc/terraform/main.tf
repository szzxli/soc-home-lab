# =============================================================================
# 01-mini-soc — Terraform: minimal AWS detection lab
#
# WHAT THIS BUILDS
#   A small, interview-ready SOC lab: VPC + an encrypted S3 log bucket,
#   a multi-region CloudTrail writing to that bucket, a GuardDuty detector,
#   a Security Hub account, and a least-privilege IAM role for analysis.
#   Nothing here runs compute, so the lab is cheap to keep alive.
#
# COST (estimates, us-west-2, minimum configuration)
#   - VPC / subnet / internet gateway / route table ............ $0.00
#   - S3 log bucket (a few GB of CloudTrail logs) ............... ~$0.10–0.50/mo
#   - CloudTrail trail: first trail with management events ...... $0.00
#       (data events and CloudTrail Insights are NOT enabled on purpose —
#        they are the expensive parts)
#   - GuardDuty: 30-day free trial for new detectors ............ $0.00
#       After the trial, S3 + EC2 protection on a quiet lab runs
#       roughly $1–4/mo. Finding publishing frequency does not change cost.
#   - Security Hub (no default standards enabled, see below) ... ~$0–2/mo
#   - IAM role / policies ....................................... $0.00
#   TOTAL: roughly $5–15/month after any free-trial period.
#   Set a billing alarm. If you only need the lab for a weekend,
#   the honest answer is that it costs pennies.
#
# REQUIREMENTS
#   - Your OWN AWS account (never run this in an employer's account).
#   - Terraform >= 1.5 and AWS CLI credentials configured
#     (e.g. `aws sts get-caller-identity` succeeds).
#   - GuardDuty and Security Hub are REGIONAL services: the region you
#     choose here is the region your findings live in. Stratus Red Team
#     techniques must be detonated in the same region.
#
# LIFECYCLE
#   terraform init
#   terraform plan
#   terraform apply
#   # ... run detections ...
#   terraform destroy   # destroys everything; the S3 bucket is force_destroy
#                       # so the destroy does not fail on leftover log objects
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  description = "AWS region for the lab. GuardDuty and Security Hub are regional, so findings live here."
  type        = string
  default     = "us-west-2"
}

variable "project_prefix" {
  description = "Prefix applied to all resource names so lab resources are easy to identify (and to nuke)."
  type        = string
  default     = "mini-soc"
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Networking: VPC + one public subnet + internet gateway.
# WHY IT EXISTS: the lab needs a realistic network boundary to talk about
# (and to attach VPC Flow Logs to later as a stretch goal). It costs nothing:
# there is no NAT gateway on purpose — a NAT gateway is ~$32/month and this
# lab runs zero EC2 instances, so it would be pure waste. The public subnet
# exists so a future analyst can launch an instance by hand if they want to.
# -----------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.project_prefix}-vpc"
    Project = var.project_prefix
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_prefix}-public"
    Project = var.project_prefix
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name    = "${var.project_prefix}-igw"
    Project = var.project_prefix
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name    = "${var.project_prefix}-public-rt"
    Project = var.project_prefix
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# -----------------------------------------------------------------------------
# S3 bucket: the immutable-ish landing zone for CloudTrail logs.
# WHY IT EXISTS: CloudTrail must write somewhere tamper-evident. A dedicated
# bucket (not a shared one) keeps the blast radius of a bucket-policy mistake
# contained, and makes "where do the logs live" a one-sentence interview answer.
# Server-side encryption (AES-256) is on because log data can contain sensitive
# API parameters; the public-access block is on because a log bucket must never
# be public — "Block public access" is the control interviewers expect you
# to name first.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.project_prefix}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # lab convenience: lets `terraform destroy` empty the bucket

  tags = {
    Name    = "${var.project_prefix}-cloudtrail-logs"
    Project = var.project_prefix
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3: no KMS key to manage, no KMS cost
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy: CloudTrail's service principal is the ONLY writer.
# WHY IT EXISTS: without this policy the trail cannot deliver logs at all —
# CloudTrail validates the bucket policy before it starts writing. It grants
# s3:GetBucketAcl (so CloudTrail can verify ownership) and s3:PutObject
# scoped to this account's AWSLogs/ prefix, with the
# bucket-owner-full-control ACL condition (the AWS-documented pattern that
# prevents cross-account object-ownership surprises).
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}

# -----------------------------------------------------------------------------
# CloudTrail: the audit trail — the single source of truth for "who did what".
# WHY IT EXISTS: GuardDuty is a black-box anomaly detector; CloudTrail is the
# raw evidence underneath it. Every triage in triage-guide.md starts with
# "check CloudTrail", and a SOC analyst who can read a CloudTrail event is
# employable. Multi-region is on so API calls in ANY region are captured —
# attackers do not limit themselves to us-west-2, and a single-region trail
# would be a coverage gap you would have to explain in an interview.
# Log file validation is on so the log files are tamper-evident
# (hash-chained digests) — that is the control behind "can we trust the logs".
# Data events and Insights are deliberately OFF: they are the expensive knobs.
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  tags = {
    Name    = "${var.project_prefix}-trail"
    Project = var.project_prefix
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# -----------------------------------------------------------------------------
# GuardDuty: the threat-detection service that turns logs into findings.
# WHY IT EXISTS: this is the "sensor" of the mini-SOC. It consumes CloudTrail,
# VPC Flow Logs, and DNS logs and emits typed findings (e.g.
# Policy:S3/BucketAnonymousAccessGranted) with severity scores — exactly the
# alert queue a Tier-1 SOC analyst triages every morning. S3 protection is on
# because scenario 1 of the attack runbook targets S3. Finding publishing is
# set to 15 minutes (fastest) so lab iterations do not waste an afternoon
# waiting on the default 6-hour batching.
# -----------------------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
  }

  tags = {
    Name    = "${var.project_prefix}-guardduty"
    Project = var.project_prefix
  }
}

# -----------------------------------------------------------------------------
# Security Hub: the findings aggregator / single pane of glass.
# WHY IT EXISTS: in a real SOC, findings come from many tools. Security Hub
# centralizes GuardDuty findings (and later, Inspector/Macie/Config) into one
# queue with a standard format (ASFF) — the "one dashboard" story. Default
# security standards are DISABLED on purpose: each enabled standard runs
# continuous Config-style checks that cost money on a quiet lab account.
# Enable them selectively later when you want a compliance-score project.
# -----------------------------------------------------------------------------
resource "aws_securityhub_account" "main" {
  enable_default_standards = false

  depends_on = [aws_guardduty_detector.main]
}

# -----------------------------------------------------------------------------
# IAM role: least-privilege access for SOC analysis work.
# WHY IT EXISTS: the lab's human (or automation) should not investigate with
# root or AdministratorAccess. This role grants ONLY what triage needs:
# reading GuardDuty/Security Hub findings, reading the log bucket, and
# looking up CloudTrail events — no ability to change infrastructure.
# Interview answer: "read-only investigation role, scoped to the log bucket".
# (Attach it to a user or assume it from the CLI when investigating.)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "soc_analyst" {
  name = "${var.project_prefix}-soc-analyst"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
      }
    ]
  })

  tags = {
    Project = var.project_prefix
  }
}

resource "aws_iam_role_policy" "soc_analyst" {
  name = "${var.project_prefix}-soc-analyst-policy"
  role = aws_iam_role.soc_analyst.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read GuardDuty findings — the alert queue being triaged.
        Sid      = "ReadGuardDutyFindings"
        Effect   = "Allow"
        Action   = ["guardduty:GetFindings", "guardduty:ListFindings", "guardduty:GetDetector"]
        Resource = "*"
      },
      {
        # Read Security Hub findings — the aggregated view.
        Sid      = "ReadSecurityHubFindings"
        Effect   = "Allow"
        Action   = ["securityhub:GetFindings", "securityhub:BatchGetSecurityControls"]
        Resource = "*"
      },
      {
        # Read the CloudTrail log bucket — raw evidence, scoped to this bucket only.
        Sid      = "ReadLogBucket"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
      },
      {
        # Look up CloudTrail events and describe the trail — "who did what, when".
        Sid      = "ReadCloudTrail"
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents", "cloudtrail:DescribeTrails"]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Outputs: the three things you need after `terraform apply`.
# -----------------------------------------------------------------------------
output "cloudtrail_log_bucket" {
  description = "S3 bucket receiving CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_trail_name" {
  description = "Name of the multi-region CloudTrail trail."
  value       = aws_cloudtrail.main.name
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID (used to query findings via CLI)."
  value       = aws_guardduty_detector.main.id
}

output "soc_analyst_role_arn" {
  description = "ARN of the least-privilege investigation role."
  value       = aws_iam_role.soc_analyst.arn
}
