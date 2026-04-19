# VulnOps Security Architecture Walkthrough

Run these commands in order during the demo. Stack must be up and all 5 pods Running before starting.

---

## 0. Confirm everything is up

```bash
kubectl get pods -n vulnops
```

Expected: 5 pods all `1/1 Running` — frontend x2, backend x2, postgres x1.

```bash
kubectl get svc -n vulnops vulnops-frontend -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

Open the URL in browser. Submit `CVE-2021-44228` (Log4Shell) — watch CVSS score and severity auto-populate from NVD.

---

## 1. Secrets management — no static credentials anywhere

```bash
# ESO pulled the DB secret from AWS Secrets Manager
kubectl get externalsecret -n vulnops
```
Expected: `STATUS=SecretSynced`, `READY=True`

```bash
# ClusterSecretStore is connected to AWS
kubectl get clustersecretstore
```
Expected: `STATUS=Valid`, `CAPABILITIES=ReadWrite`, `READY=True`

```bash
# ESO service account has NO AWS credentials — Pod Identity is the auth path
kubectl get sa external-secrets -n external-secrets -o yaml | grep role-arn
```
Expected: no output — absence of annotation proves Pod Identity, not IRSA

```bash
# Pod Identity associations — binds IAM role to K8s service accounts
aws eks list-pod-identity-associations --cluster-name vulnops-eks --profile vulnops-admin
```
Expected: two associations — ESO and EBS CSI driver

```bash
# IAM role scoped to exactly one secret ARN — no wildcards
aws iam list-attached-role-policies --role-name vulnops-external-secrets --profile vulnops-admin
```

```bash
# The materialized K8s secret — values came from Secrets Manager, not git
kubectl get secret vulnops-db-secret -n vulnops -o jsonpath='{.data.POSTGRES_USER}' | base64 -d
```
Expected: `vulnops`

---

## 2. Pod hardening

```bash
# Zero Linux capabilities — nothing to escalate with post-RCE
kubectl exec -n vulnops deploy/vulnops-backend -- cat /proc/1/status | grep CapEff
```
Expected: `CapEff: 0000000000000000`

```bash
# Running as non-root
kubectl exec -n vulnops deploy/vulnops-backend -- id
```
Expected: `uid=1000(node) gid=1000(node)`

```bash
# Read-only root filesystem — can't write webshells or persistence
kubectl exec -n vulnops deploy/vulnops-backend -- touch /test
```
Expected: `touch: /test: Read-only file system`

```bash
# All network policies
kubectl get networkpolicies -n vulnops
```
Expected: 4 policies — `default-deny-all`, `frontend-policy`, `backend-policy`, `postgres-policy`

```bash
# Postgres only accepts traffic from backend on port 5432 — no egress
kubectl describe networkpolicy postgres-policy -n vulnops
```
Expected: ingress from `app=vulnops-backend` on `5432/TCP` only, no egress allowed

---

## 3. Audit trail

```bash
# CloudTrail — multi-region, every API call captured with actor + timestamp
aws s3 ls s3://vulnops-security-logs-949642303364/cloudtrail/ --recursive | head -5
```
Expected: digest files landing across all regions

```bash
# VPC Flow Logs — full network traffic capture (ACCEPT + REJECT)
aws s3 ls s3://vulnops-security-logs-949642303364/flow-logs/ --recursive | head -5
```
Expected: flow log files landing every 5 minutes

---

## 4. IAM posture

```bash
# Access Analyzer — zero findings means nothing exposed outside the account
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:949642303364:analyzer/vulnops-access-analyzer \
  --profile vulnops-admin
```
Expected: empty findings list

---

## 5. Cost controls

```bash
# Monthly budget alert at $10
aws budgets describe-budgets --account-id 949642303364 \
  --query 'Budgets[0].{Name:BudgetName,Limit:BudgetLimit,Actual:CalculatedSpend.ActualSpend}' \
  --profile vulnops-admin
```

```bash
# Invoke TTL Lambda manually — fires SNS alert if cluster is older than 30 min
aws lambda invoke --function-name vulnops-ttl-guard /tmp/ttl-out.json \
  --profile vulnops-admin && cat /tmp/ttl-out.json
```
Expected: if cluster has been up >30 min, an alert email arrives at jalwin327@gmail.com

---

## 6. CI/CD security gates

Open: https://github.com/joshuaalwin/vulnops/actions

Walk through the last successful run:

| Stage | Tool | What it catches |
|---|---|---|
| 1 | Gitleaks | Secrets in git history |
| 2 | ESLint | Code quality |
| 3 | npm audit | Known CVEs in dependencies |
| 3b | Semgrep | SAST — eval injection, SQL injection patterns |
| 4 | Docker build + GHCR push | Image built with SBOM + provenance attached |
| 5 | Trivy | CVEs in the built container image |
| 6 | Checkov | Misconfigurations in Terraform + K8s manifests |
| 7 | Hadolint | Dockerfile best practices |
| 8 | Manifest update | ArgoCD picks up new image SHA, deploys automatically |

---

## 7. End-to-end smoke test

```bash
# Submit a CVE via API directly
curl -s -X POST http://$(kubectl get svc -n vulnops vulnops-frontend \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')/api/vulns \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-44228","title":"Log4Shell","severity":"CRITICAL","description":"Remote code execution in Log4j","affected_product":"Apache Log4j","reporter":"demo"}' \
  | jq .
```
Expected: `201` with the created record including `nvd_enriched: true` after background enrichment

```bash
# Verify it persisted to the database
curl -s http://$(kubectl get svc -n vulnops vulnops-frontend \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')/api/vulns | jq '.[0]'
```
