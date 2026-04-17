# External Secrets Operator — Install & Verify

Cluster bootstrap for ESO + AWS Secrets Manager integration via EKS Pod Identity.
Resources in this directory are **not watched by ArgoCD** (ArgoCD is scoped to `k8s/`), so installation is manual/one-shot — ESO is platform infrastructure, not app workload.

---

## Prerequisites

- Terraform applied from `terraform/` — this creates the Secrets Manager secret, IAM role, Pod Identity Agent addon, and Pod Identity association
- `kubectl` configured against the target cluster
- `helm` installed locally

---

## Install order

```bash
# 1. Install ESO via Helm — uses the external-secrets namespace + SA
#    that the Pod Identity association in Terraform is bound to.
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --values bootstrap/external-secrets/helm-values.yaml

# 2. Wait for ESO pods to be ready.
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=external-secrets \
  -n external-secrets --timeout=120s

# 3. Apply the ClusterSecretStore (cluster-wide provider config for
#    AWS Secrets Manager).
kubectl apply -f bootstrap/external-secrets/cluster-secret-store.yaml

# 4. Ensure the vulnops namespace exists (ArgoCD creates it normally —
#    run this only if applying ESO before ArgoCD sync).
kubectl create namespace vulnops --dry-run=client -o yaml | kubectl apply -f -

# 5. Apply the ExternalSecret. ESO will create/update the vulnops-db-secret
#    K8s Secret using the credentials pulled from AWS Secrets Manager.
kubectl apply -f bootstrap/external-secrets/external-secret.yaml
```

---

## Verify

```bash
# ESO pods running, no restarts
kubectl get pods -n external-secrets

# ClusterSecretStore connected successfully to AWS (expect Ready=True)
kubectl get clustersecretstore aws-secrets-manager

# ExternalSecret synced (expect Ready=True, SecretSynced reason)
kubectl get externalsecret -n vulnops vulnops-db-secret

# Materialized K8s Secret exists with the three expected keys
kubectl get secret -n vulnops vulnops-db-secret -o jsonpath='{.data}' | jq 'keys'
# → ["POSTGRES_DB","POSTGRES_PASSWORD","POSTGRES_USER"]

# Backend and postgres pods consume it — rollout to pick up any value change
kubectl rollout restart deployment/vulnops-postgres -n vulnops
kubectl rollout restart deployment/vulnops-backend -n vulnops
```

---

## Verify Pod Identity (not IRSA) is the auth path

The ESO service account must **not** carry an IRSA role annotation:

```bash
kubectl get sa -n external-secrets external-secrets -o yaml | grep -i "eks.amazonaws.com/role-arn" || echo "OK — no IRSA annotation (Pod Identity is the auth path)"
```

Confirm the Pod Identity association is bound:

```bash
aws eks list-pod-identity-associations \
  --cluster-name vulnops-eks \
  --region us-east-1 \
  --query 'associations[?namespace==`external-secrets`]'
```

---

## Rotation

Rotate the secret in AWS:

```bash
aws secretsmanager put-secret-value \
  --secret-id vulnops/db-credentials \
  --secret-string '{"POSTGRES_USER":"vulnops","POSTGRES_PASSWORD":"<new-value>","POSTGRES_DB":"vulnops"}' \
  --region us-east-1
```

Within `refreshInterval` (1 hour, set in `external-secret.yaml`), ESO re-fetches and updates the K8s Secret. Pods consuming env vars from the Secret retain the old value until restart — trigger manually:

```bash
kubectl rollout restart deployment/vulnops-postgres -n vulnops
kubectl rollout restart deployment/vulnops-backend -n vulnops
```

> Note: the Postgres database itself still has the *old* password baked in its data volume. True credential rotation requires either a `postgres` `ALTER USER` step or configuring Secrets Manager managed rotation with a rotation Lambda that runs the SQL. Out of scope for this commit — the infrastructure is in place; plumbing rotation end-to-end is a follow-up.

---

## Why this path (Pod Identity + ESO)

- **No static AWS credentials in the cluster.** ESO pods have no `AWS_ACCESS_KEY_ID` env var or credentials file. The Pod Identity Agent exchanges the projected SA token for short-lived STS credentials at call time.
- **Least-privilege IAM.** The `vulnops-external-secrets` role can call `GetSecretValue` and `DescribeSecret` on *one* secret ARN — no wildcards, no other APIs.
- **Secret rotates without redeploying.** Update the value in AWS Secrets Manager; ESO syncs it. (Pods pick up the new value on restart.)
- **One source of truth.** The password lives in AWS. Git never contains the real value. `k8s/secrets.yaml` is gone.
- **Pod Identity over IRSA** — Pod Identity is the modern AWS-recommended path: no OIDC provider ARN wiring, no trust policy conditionals on the OIDC issuer, and the service account doesn't need a magic annotation. A cleaner pattern for new deployments.
