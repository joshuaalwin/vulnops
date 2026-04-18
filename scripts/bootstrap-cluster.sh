#!/usr/bin/env bash
# Installs cluster-level tooling after `terraform apply`.
# Run from the repo root. Requires kubectl configured against vulnops-eks and helm installed.
set -euo pipefail

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

echo "Waiting for database secret to sync..."
kubectl wait externalsecret/vulnops-db-secret \
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
