#!/usr/bin/env bash
# Creates the S3 bucket and DynamoDB table that Terraform uses to store state.
# Run this once before the first `terraform init`. Do not destroy these resources.
set -euo pipefail

REGION="us-east-1"
STATE_BUCKET="vulnops-terraform-state"
LOCK_TABLE="vulnops-tf-lock"

echo "Creating Terraform backend infrastructure in ${REGION}..."

aws s3api create-bucket \
  --bucket "$STATE_BUCKET" \
  --region "$REGION"

aws s3api put-bucket-versioning \
  --bucket "$STATE_BUCKET" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket "$STATE_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-public-access-block \
  --bucket "$STATE_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws dynamodb create-table \
  --table-name "$LOCK_TABLE" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "$REGION"

echo "Done."
echo "  State bucket : s3://${STATE_BUCKET}"
echo "  Lock table   : ${LOCK_TABLE}"
