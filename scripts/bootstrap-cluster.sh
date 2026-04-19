#!/usr/bin/env bash
# Installs cluster-level tooling after `terraform apply`.
# Run from the repo root. Requires kubectl configured against vulnops-eks and helm installed.
set -euo pipefail

AI_SECRET_ID="vulnops/ai-credentials"
AWS_REGION="${AWS_REGION:-us-east-1}"
CLUSTER_NAME="${CLUSTER_NAME:-vulnops-eks}"

# Refresh kubeconfig so `kubectl` / `helm` target the cluster that Terraform just
# provisioned. Without this, a stale kubeconfig from a prior session points at a
# destroyed cluster endpoint and every subsequent step fails with a DNS error.
echo "Refreshing kubeconfig for $CLUSTER_NAME..."
aws eks update-kubeconfig \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  >/dev/null

# Seed the Anthropic API key in AWS Secrets Manager if the stored value is still
# the Terraform placeholder. Idempotent — re-running after a successful seed is a no-op.
# Set USE_ENV=1 to consume $ANTHROPIC_API_KEY from the current shell instead of prompting.
seed_ai_secret_if_needed() {
  echo "Checking Anthropic API key in AWS Secrets Manager ($AI_SECRET_ID)..."

  local current
  current="$(aws secretsmanager get-secret-value \
    --secret-id "$AI_SECRET_ID" \
    --region "$AWS_REGION" \
    --query SecretString --output text 2>/dev/null || echo "__FETCH_FAILED__")"

  if [ "$current" = "__FETCH_FAILED__" ]; then
    echo "  Could not read current secret value (AccessDenied or missing). Will attempt to seed."
  elif ! echo "$current" | grep -q "PLACEHOLDER_SEED_OUT_OF_BAND"; then
    echo "  Real key already seeded — skipping."
    return 0
  fi

  local key=""
  if [ "${USE_ENV:-0}" = "1" ]; then
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
      echo "  USE_ENV=1 set but ANTHROPIC_API_KEY is empty — aborting." >&2
      exit 1
    fi
    key="$ANTHROPIC_API_KEY"
    echo "  Using ANTHROPIC_API_KEY from environment (USE_ENV=1)."
  else
    echo ""
    echo "  Enter your Anthropic API key (input hidden). Get one at https://console.anthropic.com/."
    echo "  To use an env var instead, re-run with: USE_ENV=1 ANTHROPIC_API_KEY=... $0"
    read -rsp "  ANTHROPIC_API_KEY: " key
    echo ""
  fi

  if [ -z "$key" ] || [ "${#key}" -lt 20 ]; then
    echo "  Key looks empty or too short (<20 chars) — aborting." >&2
    exit 1
  fi

  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  trap 'rm -f "$tmp"' EXIT

  printf '{"ANTHROPIC_API_KEY":"%s"}' "$key" > "$tmp"

  aws secretsmanager put-secret-value \
    --secret-id "$AI_SECRET_ID" \
    --region "$AWS_REGION" \
    --secret-string "file://$tmp" \
    >/dev/null

  rm -f "$tmp"
  trap - EXIT

  echo "  Seeded $AI_SECRET_ID successfully."
}

seed_ai_secret_if_needed

echo "Installing External Secrets Operator..."
helm repo add external-secrets https://charts.external-secrets.io --force-update
helm repo update
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --values bootstrap/external-secrets/helm-values.yaml \
  --wait

echo "Applying ESO configuration..."
kubectl apply -f bootstrap/external-secrets/cluster-secret-store.yaml
kubectl create namespace vulnops --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f bootstrap/external-secrets/external-secret.yaml
kubectl apply -f bootstrap/external-secrets/ai-external-secret.yaml

echo "Waiting for database secret to sync..."
kubectl wait externalsecret/vulnops-db-secret \
  -n vulnops --for=condition=Ready --timeout=60s

echo "Waiting for AI secret to sync..."
kubectl wait externalsecret/vulnops-ai-secret \
  -n vulnops --for=condition=Ready --timeout=60s

echo "Installing ArgoCD..."
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
# Use `kubectl create` instead of `apply` — the ArgoCD CRD manifests exceed the
# 262144-byte annotation limit that `apply` enforces via last-applied-configuration.
kubectl create -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml \
  --save-config 2>/dev/null || true
kubectl wait --for=condition=available --timeout=120s deployment/argocd-server -n argocd

echo "Deploying application..."
kubectl apply -f k8s/argocd/application.yaml

echo "Waiting for ArgoCD initial sync..."
until kubectl get application vulnops -n argocd \
  -o jsonpath='{.status.sync.status}' 2>/dev/null | grep -q "Synced"; do
  sleep 5
done

echo "Waiting for NLB hostname..."
NLB_HOST=""
while [ -z "$NLB_HOST" ]; do
  NLB_HOST=$(kubectl get svc -n vulnops vulnops-frontend \
    -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
  [ -z "$NLB_HOST" ] && sleep 5
done

echo "Injecting ALLOWED_ORIGINS: http://$NLB_HOST"
kubectl set env deployment/vulnops-backend -n vulnops \
  ALLOWED_ORIGINS="http://$NLB_HOST"

echo ""
echo "Cluster bootstrap complete."
echo "  Frontend URL:  http://$NLB_HOST"
echo "  Watch pods:    kubectl get pods -n vulnops -w"
