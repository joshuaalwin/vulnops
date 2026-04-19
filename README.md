<p align="center">
  <img src="Vulnops-banner.svg" alt="VulnOps" width="100%"/>
</p>

# VulnOps

A CVE registry for tracking and managing vulnerabilities, built as a full-stack DevSecOps project. The application runs on AWS EKS and is deployed through a GitHub Actions CI/CD pipeline with security tooling integrated at every stage.

**Stack:** React + Nginx / Node.js Express / PostgreSQL  
**Infrastructure:** AWS EKS (Auto Mode) / Terraform / Docker / Kubernetes

---

## What it does

VulnOps lets teams submit CVEs with an ID, severity, affected product, CVSS score, description, and remediation status. Each entry supports threaded notes. There is a live CVSS v3.1 calculator on the submission form built on the official FIRST formula.

The application is deliberately simple. The security architecture around it is not: hardened containers, a locked-down Kubernetes deployment, a 10-stage CI pipeline, and AWS account-level monitoring, all provisioned through code.

<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/Vulnops-Dashboard.png" alt="VulnOps dashboard" width="110%"/>
</p>
<br><br><br>
<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/Vulnops-CVE.png" alt="VulnOps CVE submission form" width="100%"/>
</p>

The submission form includes a live CVSS v3.1 calculator built on the official FIRST formula. Scores update in real time as attack vector, complexity, privileges, and impact metrics are selected.

---

## Architecture

```
Internet -> AWS NLB -> nginx (port 8080, non-root)
                    -> React SPA (static assets)
                    -> Express API (port 5000, ClusterIP) -> PostgreSQL (port 5432, ClusterIP)
```

The backend and database are ClusterIP services with no external load balancer and no public endpoint. Only the frontend NLB is internet-facing. All three tiers run in Kubernetes on EKS. Cluster nodes sit in private subnets with a NAT gateway for outbound traffic only.

---

## Infrastructure

Provisioned entirely with Terraform using official AWS modules.

**VPC:** Three availability zones. EKS nodes in private subnets. Public subnets hold only the NAT gateway and the NLB.

**EKS Auto Mode (Kubernetes 1.32):** AWS manages node groups, CoreDNS, and kube-proxy. All five control plane log types are enabled (api, audit, authenticator, controllerManager, scheduler). Kubernetes secrets are encrypted at rest using AWS KMS envelope encryption.

**Terraform state:** S3 backend with AES256 encryption and versioning. DynamoDB table for state locking to prevent concurrent apply races.

**AWS security monitoring:**

- CloudTrail: multi-region trail with log file validation. SHA-256 digest files are generated per delivery, so any deleted or modified log breaks the chain. `include_global_service_events` is enabled because IAM and STS events always log to us-east-1 regardless of where your resources are.
- VPC Flow Logs: captures all traffic (ACCEPT and REJECT) and ships to S3. A custom log format adds pre-NAT source addresses, TCP flags, subnet ID, and VPC ID for forensic reconstruction. S3 delivery has no ingestion cost; CloudWatch Logs charges $0.50/GB.
- IAM Access Analyzer (account scope): continuously evaluates resource-based policies and flags anything accessible from outside the AWS account.
- Security logs bucket: public access fully blocked, AES256 encryption, versioning enabled, 30-day transition to STANDARD_IA, 90-day expiration.

---

## Containers

Both images use multi-stage builds: Alpine base, non-root user (UID 1000), production dependencies only.

The nginx production image is pinned to a SHA256 digest rather than a tag. Tags are mutable. A compromised upstream image under the same tag would be pulled silently. A digest is a cryptographic commitment to exact bytes.

The backend build stage intentionally uses an unpinned `node:20-alpine` to carry known CVEs. This gives the Trivy gate in CI something to detect, demonstrating that the gate actually works before the base image is upgraded.

---

## Kubernetes hardening

Every pod spec includes a full securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
automountServiceAccountToken: false
```

None of the pods need Kubernetes API access. Disabling `automountServiceAccountToken` removes an auto-mounted credential from every pod that has no use for it.

NetworkPolicies start with a default-deny baseline. Explicit allows cover only the required paths: frontend to backend on port 5000, backend to PostgreSQL on port 5432. Everything else is blocked at the network layer, including any lateral movement from a compromised frontend pod toward the database.

The `vulnops` namespace enforces Pod Security Standards at `baseline` with audit and warn set to `restricted`. The namespace is not fully restricted because PostgreSQL `initdb` requires `CAP_CHOWN` to set ownership on its data directory. Frontend and backend pods enforce restricted-equivalent controls through their own securityContexts regardless.

ArgoCD runs inside EKS and watches the `k8s/` directory in this repository. `selfHeal: true` means any manual `kubectl apply` drift is automatically reverted. CI never holds cluster credentials.

---

## CI/CD pipeline

10 stages, triggered on every push and pull request to `main`.

| Stage | Tool | What it does |
|---|---|---|
| Secret scan | Gitleaks | Full git history scan for credentials and tokens. Runs first. No point building if secrets are already exposed. |
| Lint | ESLint | Backend and frontend in parallel. |
| Dependency audit | npm audit | Fails on CRITICAL severity findings in third-party packages. |
| SAST source scan | Semgrep | Scans `backend/src/` and `frontend/src/` with `p/nodejs`, `p/owasp-top-ten`, and `p/javascript`. Results uploaded to the GitHub Security tab as SARIF. |
| SAST gate test | Semgrep | Runs `--error` against a fixture of intentionally insecure code. Inverted exit code: if Semgrep finds nothing in the fixture, the build fails. This validates the ruleset fires. A scanner that runs silently and catches nothing is worse than no scanner. |
| Build + push | Docker Buildx / GHCR | Images tagged with the 7-character commit SHA. `GITHUB_TOKEN` for auth, no stored PATs. SBOM and build provenance attestations are attached automatically via BuildKit. |
| Image scan | Trivy | Scans for OS and library CVEs across both images. |
| IaC scan | Checkov | Scans `terraform/` and `k8s/` manifests for misconfigurations. |
| Dockerfile lint | Hadolint | Fails on errors, warns on warnings. |
| Manifest update | git | Updates image tags in the backend and frontend deployment manifests. ArgoCD picks up the commit and deploys. |

Every running image is traceable to the exact commit that built it. `latest` is mutable and leaves no audit trail.

---

## Security decisions

| Decision | Rationale |
|---|---|
| `npm install --ignore-scripts` | Blocks postinstall-based supply chain attacks. Axios 1.14.1 and 0.30.4 (April 2025) were compromised to drop a RAT via the `postinstall` hook. This blocks that class of attack at install time. |
| EKS nodes in private subnets | Nodes are not directly internet-reachable. NAT gateway handles outbound only. Reduces the blast radius of a compromised node. |
| Terraform state in S3 + DynamoDB | Encrypted at rest, versioned (rollback if state is corrupted), locked against concurrent writes. |
| Nginx pinned to SHA256 digest | Image tags are mutable. Digest guarantees byte-for-byte identity regardless of what gets pushed upstream. |
| `drop: [ALL]` capabilities | Zero Linux capabilities on frontend and backend pods. Limits post-RCE impact by removing raw socket access and privilege escalation paths. |
| `readOnlyRootFilesystem: true` | Prevents writing webshells, tools, or malicious scripts to the container filesystem after compromise. |
| Default-deny NetworkPolicy | All pod-to-pod traffic is blocked by default. A compromised frontend pod cannot reach the database directly. |
| `automountServiceAccountToken: false` | Removes an auto-mounted Kubernetes API credential from every pod that does not need it. |
| GHCR over Docker Hub | CI uses the built-in `GITHUB_TOKEN`. No stored PATs, no third-party registry dependency. |
| SHA tag over `latest` | Ties every running pod to the exact commit that built it. Full traceability from cluster state back to source. |
| ArgoCD GitOps | CI never holds cluster credentials. `selfHeal` enforces git as the only write path to production. Manual drift is reverted automatically. |
| SBOM + provenance on every image | Attached automatically by BuildKit. Documents what is in the image and where it was built, satisfying SLSA and EO 14028 intent. |
| Semgrep over CodeQL for SAST | The app is simple CRUD. CodeQL taint tracking is disproportionate overhead for this codebase. Semgrep pattern rules cover the Express/Node.js attack surface and each finding maps directly to a readable rule. |
| Semgrep gate test (inverted exit code) | Semgrep exits 0 by default even when it finds vulnerabilities. The `--error` flag changes that behavior. The gate test ensures the ruleset is not silently broken or misconfigured. |
| CloudTrail multi-region + log file validation | IAM and STS events log to us-east-1 regardless of the region your resources are in. Multi-region trail captures them. SHA-256 digest chain makes deleted or modified logs detectable after the fact. |
| VPC Flow Logs to S3 | Same data as CloudWatch Logs, no ingestion cost. Custom format adds pre-NAT source addresses and TCP flags for forensic reconstruction of traffic patterns. |
| IAM Access Analyzer | Continuously flags resources with policies that grant access from outside the AWS account. Catches misconfigured policies before they become incidents. |
| Baseline PSS for postgres only | PostgreSQL `initdb` requires `CAP_CHOWN`. Frontend and backend enforce restricted-equivalent controls through their own pod specs. |
| `helmet()` on the Express API | Adds CSP, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, and five additional headers on every response. Previously the API returned bare Express defaults with no security headers. |
| CORS restricted to `ALLOWED_ORIGINS` | `cors()` with no config allows any origin. Locked to an explicit allowlist via env var. Returns 403 on disallowed origins. Server-to-server requests with no `Origin` header still pass through. |
| Rate limiting: global (200/15 min) + write (30/15 min) | Global limiter prevents request flooding. Stricter per-route limit on `POST`, `PUT`, and `DELETE` reduces write-path abuse. `RateLimit-*` headers returned on every response. |
| Input validation at the API layer | CVE IDs validated against `CVE-YYYY-NNNNN` format. Severity and status enum-checked before hitting the DB. CVSS score range enforced (0–10). Field length caps on all text inputs. Previously bad input reached the DB and surfaced as opaque 500 errors. |

---

## Running locally

**With Docker Compose:**

```bash
docker compose up --build
```

Frontend at `http://localhost`. API at `http://localhost:5000`. Database tables are created automatically on first start.

```bash
# Tear down and remove volumes
docker compose down -v
```

**Without Docker** (Node.js 20+ and PostgreSQL required):

```bash
# Create the database
sudo -u postgres psql <<EOF
CREATE USER vulnops WITH PASSWORD 'vulnops';
CREATE DATABASE vulnops OWNER vulnops;
GRANT ALL PRIVILEGES ON DATABASE vulnops TO vulnops;
\c vulnops
GRANT ALL ON SCHEMA public TO vulnops;
EOF

# Start frontend and backend together
npm install
npm run dev
```

Frontend at `http://localhost:5173`. API at `http://localhost:5000`.

---

## Deploying to AWS (EKS)

**Prerequisites:** AWS CLI configured with appropriate IAM permissions, Terraform >= 1.5, kubectl, Helm 3.

**0. Bootstrap Terraform backend (first time only):**

Terraform stores its state in an S3 bucket and uses DynamoDB to prevent concurrent writes. These need to exist before `terraform init` can run, and they sit outside the stack on purpose — they should survive every `terraform destroy`. Run the bootstrap script once:

```bash
chmod +x scripts/bootstrap-state.sh
./scripts/bootstrap-state.sh
```

This creates `vulnops-terraform-state` (versioned, AES256 encrypted, public access blocked) and `vulnops-tf-lock` (pay-per-request DynamoDB table). Combined cost at this scale is less than $0.01/month. Do not destroy them.

**1. Provision infrastructure:**

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars and set alert_email to your address
terraform init
terraform apply -var-file=terraform.tfvars
```

**2. Configure kubectl:**

```bash
aws eks update-kubeconfig --region us-east-1 --name vulnops-eks
```

**3. Bootstrap cluster tooling:**

This installs the External Secrets Operator (which pulls the database credentials from AWS Secrets Manager), waits for the secret to sync, installs ArgoCD, deploys the application, and automatically injects the live NLB hostname into the backend's CORS allowlist.

```bash
chmod +x scripts/bootstrap-cluster.sh
./scripts/bootstrap-cluster.sh
```

The script prints the frontend URL when it finishes. No manual URL lookup needed.

**4. Confirm the SNS alert subscription:**

AWS sends a confirmation email to the address in `terraform.tfvars` immediately after apply. Click the confirmation link or the cost and TTL alerts will not deliver.

From this point forward, any push to `main` that updates the image tags in the manifests triggers a deployment automatically via ArgoCD.

---

### Verifying the deployment

Once the bootstrap script completes and pods are running:

```bash
# All 5 pods should be Running
kubectl get pods -n vulnops

# Database secret synced from Secrets Manager (not from git)
kubectl get externalsecret -n vulnops

# ESO has no AWS credentials — Pod Identity is the auth path
kubectl get sa external-secrets -n external-secrets -o yaml | grep role-arn
# → no output confirms Pod Identity, not IRSA
```

See `bootstrap/external-secrets/README.md` for ESO verification steps and secret rotation instructions.

<details>
<summary>Manual setup (if you prefer to run steps individually)</summary>

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace \
  --values bootstrap/external-secrets/helm-values.yaml --wait

# Configure ESO to pull from AWS Secrets Manager
kubectl apply -f bootstrap/external-secrets/cluster-secret-store.yaml
kubectl create namespace vulnops --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f bootstrap/external-secrets/external-secret.yaml

# Wait for DB secret to sync
kubectl wait externalsecret/vulnops-db-secret -n vulnops --for=condition=Ready --timeout=60s

# Install ArgoCD
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl create -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml \
  --save-config 2>/dev/null || true
kubectl wait --for=condition=available --timeout=120s deployment/argocd-server -n argocd

# Deploy the application
kubectl apply -f k8s/argocd/application.yaml

# Inject CORS allowlist with live NLB hostname
NLB_HOST=""
while [ -z "$NLB_HOST" ]; do
  NLB_HOST=$(kubectl get svc -n vulnops vulnops-frontend \
    -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
  [ -z "$NLB_HOST" ] && sleep 5
done
kubectl set env deployment/vulnops-backend -n vulnops ALLOWED_ORIGINS="http://$NLB_HOST"
echo "Frontend URL: http://$NLB_HOST"
```

</details>

---

## Tearing down

```bash
cd terraform
terraform destroy -var-file=terraform.tfvars
```

This removes the EKS cluster, VPC, NAT gateway, security logs S3 bucket, CloudTrail trail, VPC Flow Logs, and IAM Access Analyzer. When the cluster is destroyed, all Kubernetes resources inside it (ArgoCD, ESO, all pods and namespaces) are removed automatically — no manual `kubectl delete` needed.

The security logs bucket has `force_destroy = true` so Terraform empties all versioned CloudTrail and Flow Log objects before deleting. No manual cleanup needed.

The Terraform state bucket and DynamoDB lock table are not touched — they persist across destroy cycles by design.

---

## Repository structure

```
VulnOps/
├── backend/              # Express API and database schema
├── frontend/             # React + Vite + nginx.conf
├── k8s/
│   ├── namespace.yaml
│   ├── secrets.yaml.example
│   ├── postgres/
│   ├── backend/
│   ├── frontend/
│   ├── network-policies/
│   └── argocd/
├── bootstrap/
│   └── external-secrets/ # ESO install runbook and manifests
├── terraform/            # VPC, EKS cluster, cost guard, and security monitoring
├── scripts/
│   ├── bootstrap-state.sh   # Creates S3 state bucket and DynamoDB lock table
│   └── bootstrap-cluster.sh # Installs ESO and ArgoCD after terraform apply
├── .github/workflows/    # GitHub Actions CI pipeline
├── deploy/               # EC2 setup script for manual deployment
└── docker-compose.yml
```
