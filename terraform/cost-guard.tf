# ==============================================================
# VulnOps — Cost Guard
# ==============================================================
# 1. AWS Budgets — email when monthly spend exceeds var.monthly_budget_usd
# 2. TTL Guard Lambda — email every hour if EKS cluster is still
#    alive past var.cluster_ttl_minutes (fires silently when no cluster)
# ==============================================================

# --------------------------------------------------------------
# SNS topic — single alert destination for Lambda
# --------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "vulnops-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Budgets needs permission to publish to this topic
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "budgets.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

# --------------------------------------------------------------
# AWS Budgets — alert when actual monthly spend hits the limit
# --------------------------------------------------------------
resource "aws_budgets_budget" "monthly" {
  name         = "vulnops-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }
}

# --------------------------------------------------------------
# TTL Guard Lambda
# --------------------------------------------------------------
data "archive_file" "ttl_guard" {
  type        = "zip"
  output_path = "${path.module}/ttl_guard_lambda.zip"

  source {
    filename = "handler.py"
    content  = <<-PYTHON
      import boto3, os
      from datetime import datetime, timezone

      def handler(event, context):
          eks = boto3.client("eks")
          sns = boto3.client("sns")

          try:
              cluster = eks.describe_cluster(name=os.environ["CLUSTER_NAME"])["cluster"]
          except eks.exceptions.ResourceNotFoundException:
              return

          age_minutes = (datetime.now(timezone.utc) - cluster["createdAt"]).total_seconds() / 60

          if age_minutes > int(os.environ["TTL_MINUTES"]):
              sns.publish(
                  TopicArn=os.environ["SNS_TOPIC_ARN"],
                  Subject=f"[VulnOps] EKS cluster still running after {int(age_minutes)} minutes",
                  Message=f"Run: cd terraform && terraform destroy -var-file=terraform.tfvars\n\nCluster ARN: {cluster['arn']}",
              )
    PYTHON
  }
}

resource "aws_iam_role" "ttl_guard" {
  name = "vulnops-ttl-guard"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ttl_guard" {
  name = "vulnops-ttl-guard"
  role = aws_iam_role.ttl_guard.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "eks:DescribeCluster"
        Resource = "arn:aws:eks:${var.aws_region}:${data.aws_caller_identity.current.account_id}:cluster/${var.cluster_name}"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "ttl_guard" {
  filename         = data.archive_file.ttl_guard.output_path
  source_code_hash = data.archive_file.ttl_guard.output_base64sha256
  function_name    = "vulnops-ttl-guard"
  role             = aws_iam_role.ttl_guard.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30

  environment {
    variables = {
      CLUSTER_NAME  = var.cluster_name
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      TTL_MINUTES   = tostring(var.cluster_ttl_minutes)
    }
  }
}

resource "aws_cloudwatch_event_rule" "ttl_guard" {
  name                = "vulnops-ttl-guard"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "ttl_guard" {
  rule = aws_cloudwatch_event_rule.ttl_guard.name
  arn  = aws_lambda_function.ttl_guard.arn
}

resource "aws_lambda_permission" "ttl_guard" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ttl_guard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ttl_guard.arn
}
