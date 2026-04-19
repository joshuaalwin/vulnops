# ==============================================================
# VulnOps — AWS Security Monitoring
# ==============================================================
# Resources:
#   - S3 bucket for security logs (CloudTrail + VPC Flow Logs)
#   - CloudTrail: multi-region trail, log file validation
#   - VPC Flow Logs → S3: full traffic capture (ACCEPT + REJECT)
#   - IAM Access Analyzer: detects resources exposed outside account
# ==============================================================

data "aws_caller_identity" "current" {}

# ==============================================================
# S3 — Security Logs Bucket
# Single bucket for CloudTrail and VPC Flow Logs, separated by prefix.
# Account ID in bucket name guarantees global uniqueness.
# ==============================================================

resource "aws_s3_bucket" "security_logs" {
  bucket        = "vulnops-security-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Block all public access — audit logs must never be publicly readable
resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption — log files contain sensitive API call metadata
resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning — protects against accidental deletion of log files
resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle — keep logs hot for 30 days, transition to cheaper IA tier,
# expire at 90 days. Adjust expiration upward in production.
resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "security-logs-lifecycle"
    status = "Enabled"

    filter {} # applies to all objects in the bucket

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.security_logs]
}

# Bucket policy — grants CloudTrail and VPC Flow Logs service principals
# write access. Scoped by SourceArn and prefix to prevent confused deputy attacks.
resource "aws_s3_bucket_policy" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  policy = data.aws_iam_policy_document.security_logs_policy.json

  # Public access block must be in place before bucket policy is applied
  depends_on = [aws_s3_bucket_public_access_block.security_logs]
}

data "aws_iam_policy_document" "security_logs_policy" {
  # CloudTrail needs to verify it can write to the bucket before creating the trail
  statement {
    sid    = "CloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.security_logs.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/vulnops-trail"]
    }
  }

  # CloudTrail: write log files under the cloudtrail/ prefix
  statement {
    sid    = "CloudTrailPutObject"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.security_logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/vulnops-trail"]
    }
  }

  # VPC Flow Logs: check bucket ACL before delivering
  statement {
    sid    = "FlowLogsAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.security_logs.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # VPC Flow Logs: write log files under the flow-logs/ prefix
  statement {
    sid    = "FlowLogsPutObject"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.security_logs.arn}/flow-logs/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# ==============================================================
# CloudTrail
# ==============================================================
# Multi-region trail captures API calls across all regions,
# not just us-east-1 — important because IAM, STS, and other
# global services log to us-east-1 but must be captured globally.
#
# Log file validation: CloudTrail generates a hash digest for each
# log file. If a log is deleted or modified after delivery, the
# digest chain breaks — tamper-evident audit trail.
# ==============================================================

resource "aws_cloudtrail" "main" {
  name           = "vulnops-trail"
  s3_bucket_name = aws_s3_bucket.security_logs.id
  s3_key_prefix  = "cloudtrail"

  # Capture API calls in every region, not just the home region
  is_multi_region_trail = true

  # Include IAM, STS, CloudFront — global services that log to us-east-1
  include_global_service_events = true

  # SHA-256 digest file for each log delivery — detects tampering or deletion
  enable_log_file_validation = true

  depends_on = [aws_s3_bucket_policy.security_logs]
}

# ==============================================================
# VPC Flow Logs → S3
# ==============================================================
# Captures all traffic metadata (src/dst IP, port, protocol,
# accept/reject) for the VulnOps VPC.
#
# traffic_type = ALL: capture both accepted and rejected traffic.
# Rejected traffic is often more interesting — port scans, blocked
# lateral movement, failed exfiltration attempts show up here.
#
# Custom log format adds fields not in the default format:
# vpc-id, subnet-id, tcp-flags, pkt-srcaddr/dstaddr (original
# source before NAT) — useful for forensic reconstruction.
#
# Sending to S3 instead of CloudWatch Logs: no ingestion cost
# ($0.50/GB with CWL vs free with S3), same data.
# ==============================================================

resource "aws_flow_log" "vpc" {
  vpc_id               = module.vpc.vpc_id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.security_logs.arn}/flow-logs/"

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"

  depends_on = [aws_s3_bucket_policy.security_logs]
}

# ==============================================================
# IAM Access Analyzer
# ==============================================================
# Continuously analyzes resource-based policies to identify
# S3 buckets, IAM roles, KMS keys, SQS queues, and Lambda
# functions that are accessible from outside this AWS account.
#
# type = ACCOUNT: scope is the entire account — any resource
# with a policy granting access to external principals is flagged.
# Findings appear in the IAM console and can be exported.
# ==============================================================

resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "vulnops-access-analyzer"
  type          = "ACCOUNT"
}
