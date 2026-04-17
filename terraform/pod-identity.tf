# ==============================================================
# VulnOps — EKS Pod Identity + AWS Secrets Manager + ESO
# ==============================================================
# Replaces the static k8s/secrets.yaml DB credentials with an
# AWS-Secrets-Manager-backed secret, consumed by the cluster via
# the External Secrets Operator (ESO) authenticated through EKS
# Pod Identity — no static AWS credentials in the cluster.
#
# Runtime flow:
#   AWS Secrets Manager (vulnops/db-credentials)
#        │  GetSecretValue
#        ▼
#   ESO controller pod (ns: external-secrets, SA: external-secrets)
#        │  exchanges projected SA token for short-lived IAM creds
#        ▼
#   EKS Pod Identity Agent (kube-system)
#        │  sts:AssumeRoleForPodIdentity
#        ▼
#   IAM role: vulnops-external-secrets
#   (policy scoped to GetSecretValue on one secret ARN)
# ==============================================================

# --------------------------------------------------------------
# Random initial password — Terraform owns generation so the
# value never enters git. `ignore_changes` on the secret version
# means rotation outside Terraform (e.g. manual or Lambda-driven)
# will not be reverted by a future `terraform apply`.
# --------------------------------------------------------------
resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}:?"
}

# --------------------------------------------------------------
# Secrets Manager secret
# --------------------------------------------------------------
# recovery_window_in_days = 7:
#   Standard default. 0 means immediate delete (foot-gun in prod).
#   30 is the max. 7 balances recoverability against cleanup speed.
# --------------------------------------------------------------
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "vulnops/db-credentials"
  description             = "Postgres credentials for the vulnops backend and postgres pods"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id

  # Stored as JSON — ESO's ExternalSecret extracts each property
  # into its own key in the materialized K8s Secret. Matches the
  # three keys the backend and postgres deployments expect.
  secret_string = jsonencode({
    POSTGRES_USER     = "vulnops"
    POSTGRES_PASSWORD = random_password.db_password.result
    POSTGRES_DB       = "vulnops"
  })

  # Allow out-of-band rotation without Terraform fighting the change.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# --------------------------------------------------------------
# IAM role for External Secrets Operator
# --------------------------------------------------------------
# Trust policy principal `pods.eks.amazonaws.com` is the Pod
# Identity service principal. Scoped to sts:AssumeRole +
# sts:TagSession only — no other STS actions are needed or allowed.
# --------------------------------------------------------------
data "aws_iam_policy_document" "eso_trust" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    actions = [
      "sts:AssumeRole",
      "sts:TagSession"
    ]
  }
}

resource "aws_iam_role" "external_secrets" {
  name               = "vulnops-external-secrets"
  assume_role_policy = data.aws_iam_policy_document.eso_trust.json
  description        = "Assumed by the external-secrets SA via EKS Pod Identity"
}

# --------------------------------------------------------------
# Least-privilege policy
# --------------------------------------------------------------
# GetSecretValue  — required for ESO to pull the secret
# DescribeSecret  — required for ESO to determine rotation metadata
# Both scoped to exactly one ARN — no wildcards.
# --------------------------------------------------------------
data "aws_iam_policy_document" "eso_read_db_credentials" {
  statement {
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]

    resources = [aws_secretsmanager_secret.db_credentials.arn]
  }
}

resource "aws_iam_policy" "external_secrets" {
  name        = "vulnops-external-secrets-read"
  description = "Read-only access to the vulnops/db-credentials secret for ESO"
  policy      = data.aws_iam_policy_document.eso_read_db_credentials.json
}

resource "aws_iam_role_policy_attachment" "external_secrets" {
  role       = aws_iam_role.external_secrets.name
  policy_arn = aws_iam_policy.external_secrets.arn
}

# --------------------------------------------------------------
# EKS Pod Identity Agent addon
# --------------------------------------------------------------
# EKS Auto Mode does not bundle the Pod Identity Agent — it must
# be installed as a cluster addon. Without the agent, the
# pod-identity-association below is a no-op: pods receive no
# short-lived credentials and AWS SDK calls fall back to the
# instance profile (which has no Secrets Manager access).
# --------------------------------------------------------------
resource "aws_eks_addon" "pod_identity_agent" {
  cluster_name                = module.eks.cluster_name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}

# --------------------------------------------------------------
# Pod Identity association
# --------------------------------------------------------------
# Binds the IAM role to the external-secrets service account in
# the external-secrets namespace. When ESO calls Secrets Manager,
# the Pod Identity Agent intercepts the request, exchanges the
# projected SA token for STS credentials under this role, and
# injects them transparently. No kubernetes Secret ever holds
# AWS credentials.
# --------------------------------------------------------------
resource "aws_eks_pod_identity_association" "external_secrets" {
  cluster_name    = module.eks.cluster_name
  namespace       = "external-secrets"
  service_account = "external-secrets"
  role_arn        = aws_iam_role.external_secrets.arn

  depends_on = [aws_eks_addon.pod_identity_agent]
}

# --------------------------------------------------------------
# Outputs — consumed by the ESO manifests in bootstrap/
# --------------------------------------------------------------
output "external_secrets_role_arn" {
  value       = aws_iam_role.external_secrets.arn
  description = "IAM role ARN assumed by the external-secrets SA via Pod Identity"
}

output "db_credentials_secret_arn" {
  value       = aws_secretsmanager_secret.db_credentials.arn
  description = "Secrets Manager secret ARN referenced by the ExternalSecret"
}

output "db_credentials_secret_name" {
  value       = aws_secretsmanager_secret.db_credentials.name
  description = "Secrets Manager secret name referenced by the ExternalSecret"
}
