# VulnOps — Security Controls Verification Guide

This guide walks through verifying every security control implemented in VulnOps. Each section covers a distinct layer of the security architecture — from runtime pod hardening to CI/CD gate enforcement. Commands are designed to produce deterministic output so you can confirm each control is active rather than just deployed.

**Prerequisites:** Stack deployed and healthy. Set your environment variables before starting:

```bash
export CLUSTER_NAME=vulnops-eks
export AWS_PROFILE=<your-aws-profile>
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile $AWS_PROFILE)
```

Confirm all pods are running before proceeding:

```bash
kubectl get pods -n vulnops
```

Expected: 5 pods all `1/1 Running` — frontend ×2, backend ×2, postgres ×1.

---

## 1. Secrets Management

VulnOps uses External Secrets Operator (ESO) with EKS Pod Identity to pull credentials from AWS Secrets Manager at runtime. No credentials are stored in git, Kubernetes manifests, or environment variables baked into container images.

```bash
# ESO synced the DB secret from Secrets Manager
kubectl get externalsecret -n vulnops
```
Expected: `STATUS=SecretSynced`, `READY=True`

```bash
# ClusterSecretStore is authenticated to AWS
kubectl get clustersecretstore
```
Expected: `STATUS=Valid`, `CAPABILITIES=ReadWrite`, `READY=True`

```bash
# ESO service account carries no AWS credentials — Pod Identity is the auth path
kubectl get sa external-secrets -n external-secrets -o yaml | grep role-arn
```
Expected: no output. The absence of an IRSA annotation confirms Pod Identity is in use — credentials are injected per-pod by the EKS agent, not stored as annotations.

```bash
# Pod Identity associations — IAM role bound to K8s service accounts at the cluster level
aws eks list-pod-identity-associations --cluster-name $CLUSTER_NAME --profile $AWS_PROFILE
```
Expected: two associations — one for ESO, one for the EBS CSI driver.

```bash
# IAM role is scoped to exactly one secret ARN — no wildcards
aws iam list-attached-role-policies --role-name vulnops-external-secrets --profile $AWS_PROFILE
```

```bash
# The materialized K8s secret — value sourced from Secrets Manager, not from git
kubectl get secret vulnops-db-secret -n vulnops -o jsonpath='{.data.POSTGRES_USER}' | base64 -d
```
Expected: `vulnops`

---

## 2. Pod Hardening

Every pod runs with a hardened `securityContext`: non-root UID, read-only root filesystem, and all Linux capabilities dropped. These controls limit what an attacker can do if they achieve code execution inside a container.

```bash
# All Linux capabilities dropped — CapEff of 0 means no kernel-level escalation path
kubectl exec -n vulnops deploy/vulnops-backend -- cat /proc/1/status | grep CapEff
```
Expected: `CapEff: 0000000000000000`

```bash
# Process runs as non-root
kubectl exec -n vulnops deploy/vulnops-backend -- id
```
Expected: `uid=1000(node) gid=1000(node)`

```bash
# Read-only root filesystem — prevents writing webshells or persistence artifacts
kubectl exec -n vulnops deploy/vulnops-backend -- touch /test
```
Expected: `touch: /test: Read-only file system`

---

## 3. Network Policies

Network policies enforce a default-deny posture at the pod level. Traffic between tiers is explicitly allowlisted — the database accepts connections only from the backend on port 5432, and has no egress permitted.

```bash
# Four policies in place
kubectl get networkpolicies -n vulnops
```
Expected: `default-deny-all`, `frontend-policy`, `backend-policy`, `postgres-policy`

```bash
# Postgres policy: ingress from backend only on 5432, no egress
kubectl describe networkpolicy postgres-policy -n vulnops
```
Expected: ingress rule from `app=vulnops-backend` on `5432/TCP` only, no egress block defined (egress denied by `default-deny-all`).

---

## 4. Audit Trail

CloudTrail and VPC Flow Logs are enabled at the account level. Every AWS API call is recorded with actor identity and timestamp. Flow logs capture all accepted and rejected network traffic at the VPC level.

```bash
# CloudTrail delivering logs across all regions
aws s3 ls s3://vulnops-security-logs-${AWS_ACCOUNT_ID}/cloudtrail/ --recursive --profile $AWS_PROFILE | head -5
```
Expected: digest files landing across multiple regions.

```bash
# VPC Flow Logs — traffic captured at 5-minute intervals
aws s3 ls s3://vulnops-security-logs-${AWS_ACCOUNT_ID}/flow-logs/ --recursive --profile $AWS_PROFILE | head -5
```
Expected: flow log files arriving every 5 minutes.

---

## 5. IAM Posture

IAM Access Analyzer monitors for resources unintentionally exposed outside the account boundary. A clean findings list confirms no S3 buckets, IAM roles, or KMS keys are accessible externally.

```bash
# Access Analyzer — zero findings means no resources exposed outside the account
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:${AWS_ACCOUNT_ID}:analyzer/vulnops-access-analyzer \
  --profile $AWS_PROFILE
```
Expected: empty `findings` array.

---

## 6. Cost Controls

A TTL Lambda fires an SNS alert if the EKS cluster has been running for more than 30 minutes without being torn down — preventing forgotten infrastructure from accruing cost.

```bash
# Monthly budget configured
aws budgets describe-budgets --account-id $AWS_ACCOUNT_ID \
  --query 'Budgets[0].{Name:BudgetName,Limit:BudgetLimit,Actual:CalculatedSpend.ActualSpend}' \
  --profile $AWS_PROFILE
```

```bash
# Invoke the TTL guard manually to verify it fires
aws lambda invoke --function-name vulnops-ttl-guard /tmp/ttl-out.json \
  --profile $AWS_PROFILE && cat /tmp/ttl-out.json
```
Expected: if the cluster has been up longer than the threshold, the function returns a non-zero alert status and sends an SNS notification.

---

## 7. CI/CD Security Gates

Every push to `main` runs a multi-stage pipeline before any image is deployed. Each gate enforces a hard failure — findings are not warnings.

| Stage | Tool | What it enforces |
|---|---|---|
| 1 | Gitleaks | No secrets in git history or staged files |
| 2 | ESLint | Code quality baseline |
| 3 | npm audit | No CRITICAL CVEs in application dependencies |
| 3b | Semgrep | SAST — injection patterns, OWASP Top 10 |
| 3c | Semgrep gate test | Validates Semgrep rules are active (inverted exit code) |
| 4 | Docker build + GHCR push | Image built with SBOM and provenance attestation |
| 5 | Trivy | No unfixed CRITICAL or HIGH CVEs in the container image |
| 6 | Checkov | Misconfigurations in Terraform and K8s manifests |
| 7 | Hadolint | Dockerfile best-practice violations |
| 8 | Manifest update | ArgoCD detects new image SHA and deploys automatically |

View pipeline history: https://github.com/joshuaalwin/vulnops/actions

---

## 8. End-to-End Smoke Test

Verify the full application stack is reachable and data flows correctly through all three tiers.

```bash
export APP_HOST=$(kubectl get svc -n vulnops vulnops-frontend \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Submit a CVE — NVD enrichment runs asynchronously in the background
curl -s -X POST http://${APP_HOST}/api/vulns \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2021-44228",
    "title": "Log4Shell",
    "severity": "CRITICAL",
    "description": "Remote code execution via JNDI lookup in Apache Log4j 2.x",
    "affected_product": "Apache Log4j",
    "reporter": "security-team"
  }' | jq .
```
Expected: `201` response with the created record. After a few seconds, re-fetch the record to confirm `nvd_enriched: true` and CVSS fields populated from NVD.

```bash
# Confirm the record persisted to the database tier
curl -s http://${APP_HOST}/api/vulns | jq '.[0]'
```
