<p align="center">
  <img src="Vulnops-banner.svg" alt="VulnOps" width="100%"/>
</p>

# VulnOps

> **A DevSecOps reference architecture on AWS EKS** — security controls enforced at every layer, provisioned through Terraform, deployed through a 10-stage GitHub Actions pipeline, and reconciled by ArgoCD with zero long-lived credentials.

<p align="center">
  <a href="https://github.com/joshuaalwin/vulnops/actions/workflows/ci.yml"><img src="https://github.com/joshuaalwin/vulnops/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/SBOM-attached-10b981" alt="SBOM attached">
  <img src="https://img.shields.io/badge/Provenance-SLSA-3b82f6" alt="SLSA provenance">
  <img src="https://img.shields.io/badge/EKS-AutoMode%20%7C%20v1.32-fbbf24" alt="EKS Auto Mode v1.32">
  <img src="https://img.shields.io/badge/Terraform-%E2%89%A51.5-7c3aed" alt="Terraform">
  <img src="https://img.shields.io/badge/AI--enriched-Claude-c2410c" alt="AI-enriched with Claude">
</p>

---

## Contents

[The application](#the-application) · [Features in action](#features-in-action) · [Architecture](#architecture) · [What this demonstrates](#what-this-demonstrates) · [Design decisions](#design-decisions) · [Threat intelligence & AI](#threat-intelligence--ai) · [Security architecture](#security-architecture) · [CI/CD gates](#cicd-security-gates) · [Walkthrough](#walkthrough) · [Deploy](#deploying-to-aws) · [Tear down](#tearing-down) · [AI disclosure](#ai-disclosure)

---

## The application

VulnOps lets teams submit CVEs with an ID, severity, affected product, CVSS score, description, and remediation status. Each entry supports threaded notes. The submission form includes a live CVSS v3.1 calculator built on the official FIRST formula — scores update in real time as attack vector, complexity, privileges, and impact metrics are selected.

<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/All-Vulns.png" alt="VulnOps vulnerability registry" width="100%"/>
</p>

---

## Features in action

### Auto-enrichment from NVD

<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/NVD-Lookup.png" alt="NVD auto-enrichment" width="90%"/>
</p>

On CVE submission, the backend pulls CVSS, CWE, and affected-version data directly from the NIST NVD API — no manual severity entry required.

### Structured vulnerability record

<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/Vuln-description.png" alt="Vulnerability detail view" width="90%"/>
</p>

Each CVE stores the NVD description, affected product metadata, EPSS exploit-prediction score, and CISA KEV status in one auditable record.

### AI-generated risk intelligence

<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/AI-Risk.png" alt="Claude risk synthesis" width="90%"/>
</p>

Claude Sonnet 4.6 synthesizes CVSS, EPSS, KEV, and product context into a composite risk score, compliance mappings (PCI DSS, SOX ITGC, NIST CSF, CIS v8), and prioritized remediation actions. Streamed via SSE with prompt caching.

---

## Architecture

<p align="center">
  <img src="https://github.com/joshuaalwin/vulnops/releases/download/static-assets/VulnOps-Architecture.png" alt="VulnOps architecture" width="100%"/>
</p>

CI authenticates to AWS with a short-lived OIDC token, builds images into GHCR with provenance attached, and commits a SHA-tagged manifest back to git. ArgoCD syncs the cluster from there — no CI credentials touch it. Pods call Secrets Manager through the Pod Identity Agent, which swaps a projected service account token for a 15-minute STS credential scoped to one ARN. The NLB is the only public endpoint; backend and database are ClusterIP behind default-deny NetworkPolicies.

---

## What this demonstrates

| Domain | Controls |
|---|---|
| **Identity & access** | EKS Pod Identity (no IRSA, no static keys); GitHub Actions → AWS via OIDC federation; IAM Access Analyzer monitoring cross-account exposure |
| **Network isolation** | EKS in private subnets; default-deny NetworkPolicy baseline with explicit per-tier allows; NLB as the only internet ingress |
| **Secrets management** | External Secrets Operator pulls from AWS Secrets Manager; Kubernetes secrets encrypted at rest via KMS envelope encryption; zero plaintext credentials in git |
| **Supply chain integrity** | SBOM and SLSA build provenance attached to every image; `npm install --ignore-scripts`; nginx pinned to SHA256 digest; commit-SHA image tags only |
| **Runtime hardening** | `runAsNonRoot`, `readOnlyRootFilesystem`, `drop: [ALL]` capabilities, `automountServiceAccountToken: false`, Pod Security Standards enforcement |
| **Audit & detection** | Multi-region CloudTrail with log-file validation; VPC Flow Logs to S3 with custom format; encrypted log bucket with 90-day lifecycle; five EKS control-plane log types enabled |
| **Threat intel & AI** | Auto-enrichment from NVD (CVSS), FIRST EPSS (exploit prediction), and CISA KEV (known-exploited); Claude-generated risk rationale with prompt caching |

---

## Design decisions

Every decision is opinionated and defensible in a cloud security review.

### Identity & access

| Decision | Rationale |
|---|---|
| EKS Pod Identity over IRSA | No OIDC provider to maintain, no role-arn annotations to audit. IAM binding is visible through `aws eks list-pod-identity-associations`. |
| OIDC federation for GitHub Actions → AWS | No long-lived `AWS_ACCESS_KEY_ID` in GitHub secrets. CI credentials are minted per-workflow, scoped by trust policy, and expire in 1 hour. |
| IAM Access Analyzer at account scope | Continuously flags resources with policies that grant access from outside the AWS account. Catches misconfigured policies before they become incidents. |

### Network isolation

| Decision | Rationale |
|---|---|
| EKS nodes in private subnets | Nodes are not directly internet-reachable. NAT gateway handles outbound only. Reduces the blast radius of a compromised node. |
| Default-deny NetworkPolicy | All pod-to-pod traffic is blocked by default. A compromised frontend pod cannot reach the database directly. |
| ClusterIP for backend and database | No external load balancer, no public endpoint. Only the frontend NLB is internet-facing. |

### Secrets management

| Decision | Rationale |
|---|---|
| External Secrets Operator + AWS Secrets Manager | Git is not a secrets store. Credentials live in Secrets Manager with rotation, versioning, and audit logging. ESO materializes them into Kubernetes on reconciliation. |
| `ClusterSecretStore` scoped to a single secret ARN | No wildcards. The IAM role attached to ESO can read exactly one secret. |
| Kubernetes secret encryption via KMS | Enabled on the EKS cluster. Secrets stored in etcd are envelope-encrypted. |

### Supply chain integrity

| Decision | Rationale |
|---|---|
| `npm install --ignore-scripts` | Blocks postinstall-based supply chain attacks. Axios 1.14.1 and 0.30.4 (April 2025) were compromised to drop a RAT via the `postinstall` hook. |
| Nginx pinned to SHA256 digest | Tags are mutable. Digest guarantees byte-for-byte identity regardless of what gets pushed upstream. |
| SBOM + SLSA provenance on every image | Attached automatically by BuildKit. Documents what is in the image and where it was built, satisfying SLSA and EO 14028 intent. |
| SHA tag over `latest` | Ties every running pod to the exact commit that built it. Full traceability from cluster state back to source. |
| GHCR over Docker Hub | CI uses the built-in `GITHUB_TOKEN`. No stored PATs, no third-party registry dependency. |
| Semgrep gate test (inverted exit code) | Semgrep exits 0 by default even when it finds vulnerabilities. The `--error` flag changes that. The gate test ensures the ruleset is not silently broken. A scanner that catches nothing is worse than no scanner. |
| Semgrep over CodeQL for SAST | The app is simple CRUD. CodeQL taint tracking is disproportionate overhead. Semgrep pattern rules cover the Express/Node.js attack surface, each finding maps directly to a readable rule. |

### Runtime hardening

| Decision | Rationale |
|---|---|
| `drop: [ALL]` capabilities | Zero Linux capabilities on frontend and backend pods. Limits post-RCE impact by removing raw socket access and privilege escalation paths. |
| `readOnlyRootFilesystem: true` | Prevents writing webshells, tools, or malicious scripts to the container filesystem after compromise. |
| `automountServiceAccountToken: false` | Removes an auto-mounted Kubernetes API credential from every pod that does not need it. |
| Baseline PSS for postgres only | PostgreSQL `initdb` requires `CAP_CHOWN`. Frontend and backend enforce restricted-equivalent controls through their own pod specs. |
| ArgoCD GitOps with `selfHeal` | CI never holds cluster credentials. Git is the only write path to production. Manual drift is reverted automatically. |
| `helmet()` on the Express API | Adds CSP, HSTS, and seven other headers on every response. Previously the API returned bare Express defaults. |
| CORS restricted to `ALLOWED_ORIGINS` | `cors()` with no config allows any origin. Locked to an explicit allowlist via env var. |
| Rate limiting: global (200/15 min) + write (30/15 min) | Global limiter prevents flooding. Stricter per-route limit on write paths reduces abuse. |
| Input validation at the API layer | CVE IDs validated against `CVE-YYYY-NNNNN`. Severity and status enum-checked. CVSS score bounded 0–10. Field length caps on all text inputs. |

### Audit & detection

| Decision | Rationale |
|---|---|
| CloudTrail multi-region + log file validation | IAM and STS events log to us-east-1 regardless of resource region. Multi-region trail captures them. SHA-256 digest chain makes tampering detectable after the fact. |
| VPC Flow Logs to S3 | Same data as CloudWatch Logs, no ingestion cost. Custom format adds pre-NAT source addresses and TCP flags for forensic reconstruction. |
| Terraform state in S3 + DynamoDB | Encrypted at rest, versioned (rollback if state is corrupted), locked against concurrent writes. |
| Security logs bucket with `force_destroy = true` | 90-day lifecycle, public access blocked, versioning on. `force_destroy` lets `terraform destroy` clean up without a manual `aws s3 rm` step. |

---

## Threat intelligence & AI

Every submitted CVE is asynchronously enriched from authoritative sources, then run through a Claude-generated risk rationale. The application turns a bare CVE ID into a prioritized, context-aware record without manual lookup.

### Enrichment pipeline

| Source | What it adds | Cache |
|---|---|---|
| **NVD (NIST)** | Official CVSS v3.1 vector + base score, weakness enumeration (CWE), vulnerable product range, authoritative description. Backfilled if the user submits only an ID. | per-CVE, refreshed on miss |
| **FIRST EPSS** | Exploit Prediction Scoring System — probability (0–1) that the CVE will be exploited in the next 30 days, ranked against the global EPSS distribution. | 24h |
| **CISA KEV** | Binary flag: is this CVE in the Known Exploited Vulnerabilities catalog? Drives prioritization — a low-CVSS CVE with active exploitation outranks a high-CVSS CVE with none. | 24h catalog refresh |

Enrichment is fire-and-forget from the user's perspective. A CVE submitted without CVSS comes back with full NVD metadata, EPSS score, and KEV status on the next page refresh.

### AI risk rationale

Each record gets a structured risk assessment generated by the **Anthropic Claude API** (streaming response). The rationale is grounded in the enriched data — CVSS vector, EPSS percentile, KEV status — and reasons about:

- **Exploitability** — what access and preconditions an attacker needs
- **Blast radius** — what a successful exploit unlocks (data exposure, lateral movement, RCE)
- **Prioritization** — where this CVE should sit in the remediation queue relative to the rest of the backlog
- **Remediation posture** — whether a patch, mitigation, or compensating control is the right next step

Implementation detail:

- **Streaming responses** via the Anthropic SDK — rationale renders incrementally as tokens arrive, no spinner-staring
- **Prompt caching** on the enrichment context (system prompt + scoring rubric) — repeated scoring calls hit the cache, cutting cost and latency
- **7-day result cache** keyed on `(cve_id, enrichment_hash)` — identical inputs don't re-spend tokens
- **Score rationale cap** at 1500 characters — enforced in validation, prevents runaway generation
- **Grounding check** — the response is validated to reference the source data, not hallucinate CVE details

### Why this matters

A CVE registry that just stores IDs is a spreadsheet. The enrichment + AI layer turns it into a triage tool:

- **NVD** tells you the technical shape of the vulnerability
- **EPSS** tells you how likely it is to be exploited in practice
- **KEV** tells you if it's actively being exploited *right now*
- **Claude** synthesizes all three into a decision — patch now, patch soon, or accept the risk

This is the same data model a production vulnerability management platform uses. Built on public APIs and one LLM call.

---

## Security architecture

### 1. Identity & access

EKS Pod Identity binds IAM roles to Kubernetes service accounts without OIDC provider annotations — no role-arn annotations, no long-lived access keys on the cluster. GitHub Actions mints short-lived OIDC credentials per workflow; no `AWS_ACCESS_KEY_ID` in GitHub secrets. IAM Access Analyzer runs at account scope and flags any resource exposed outside the AWS account.

<details>
<summary>Read more</summary>

EKS Pod Identity associations bind IAM roles to Kubernetes service accounts without OIDC provider annotations. External Secrets Operator and the EBS CSI driver authenticate to AWS through Pod Identity — no IRSA role-arn annotations, no long-lived access keys anywhere on the cluster.

GitHub Actions authenticates to AWS through OIDC federation. The CI job exchanges a short-lived GitHub-signed token for AWS credentials scoped per workflow. No PATs, no `AWS_ACCESS_KEY_ID` stored as a repo secret.

IAM Access Analyzer runs at account scope and continuously flags resources with policies that grant access from outside the AWS account. Zero findings is the steady state.

</details>

### 2. Network isolation

Nodes sit in private subnets; the NLB is the only internet-facing resource. Default-deny NetworkPolicies block all pod-to-pod traffic — frontend reaches backend on port 5000, backend reaches PostgreSQL on 5432, nothing else crosses tier boundaries.

<details>
<summary>Read more</summary>

Three availability zones. Public subnets hold only the NAT gateway and the NLB; everything else — EKS nodes, the PostgreSQL StatefulSet — sits in private subnets with egress through NAT.

```
Internet → NLB (public subnet) → nginx pods (8080, non-root)
                              → React SPA (static assets)
                              → Express API (5000, ClusterIP) → PostgreSQL (5432, ClusterIP)
```

The backend and database are ClusterIP services with no external load balancer and no public endpoint. Only the frontend NLB is internet-facing.

NetworkPolicies start with a default-deny baseline in the `vulnops` namespace. Explicit allows cover only the required paths: frontend → backend on port 5000, backend → PostgreSQL on port 5432. Lateral movement from a compromised frontend pod toward the database is blocked at the network layer.

</details>

### 3. Secrets management

External Secrets Operator pulls credentials from AWS Secrets Manager and materializes them as Kubernetes secrets. The `ClusterSecretStore` is scoped to a single secret ARN — no wildcards. Secrets in etcd are envelope-encrypted via KMS.

<details>
<summary>Read more</summary>

External Secrets Operator (ESO) pulls database credentials from AWS Secrets Manager and materializes them as a Kubernetes secret in the `vulnops` namespace. The `ClusterSecretStore` is scoped to a single secret ARN — no wildcards.

Kubernetes secrets are encrypted at rest using AWS KMS envelope encryption (configured on the EKS cluster). `k8s/secrets.yaml` is gitignored; only `secrets.yaml.example` is tracked.

For rotation, AWS Secrets Manager is the source of truth. Rotating the value there triggers an ESO re-sync on the next reconciliation interval; no manifest change, no redeploy.

</details>

### 4. Supply chain integrity

`npm install --ignore-scripts` blocks postinstall attacks. Images are multi-stage Alpine builds with nginx pinned to a SHA256 digest, tagged with commit SHAs, and shipped with SBOM and SLSA provenance attached by BuildKit. ArgoCD syncs from git; CI never touches the cluster directly.

<details>
<summary>Read more</summary>

**Source:**
- `npm install --ignore-scripts` blocks postinstall-based supply chain attacks (Axios 1.14.1/0.30.4 compromise, April 2025, dropped a RAT via `postinstall`).
- Gitleaks runs first in CI — no point building if secrets are already exposed.
- Semgrep SAST runs two passes: the real scan, and an inverted-exit-code gate test against intentionally vulnerable code that fails the build if the ruleset doesn't fire.

**Build:**
- Multi-stage Dockerfiles, Alpine base, non-root user (UID 1000), production dependencies only.
- Nginx pinned to a SHA256 digest. Tags are mutable; a compromised upstream image under the same tag would be pulled silently. A digest is a cryptographic commitment to exact bytes.
- The backend build stage intentionally uses an unpinned `node:20-alpine` to carry known CVEs. This gives the Trivy gate something to detect, demonstrating the gate actually works before the base image is upgraded.

**Distribute:**
- Images pushed to GHCR with SBOM and SLSA provenance attestations attached by BuildKit.
- Images tagged with the 7-character commit SHA. Every running pod is traceable to the exact commit that built it.
- `GITHUB_TOKEN` handles auth — no stored PATs, no third-party registry dependency.

**Deploy:**
- ArgoCD reconciles `k8s/` from git with `selfHeal: true`. Manual `kubectl apply` drift is automatically reverted. CI never holds cluster credentials.

</details>

### 5. Runtime hardening

Every pod drops all Linux capabilities, runs as UID 1000 on a read-only filesystem, and has `automountServiceAccountToken: false`. The Express API adds helmet headers, CORS locked to an explicit allowlist, rate limiting, and input validation on all fields.

<details>
<summary>Read more</summary>

Every pod spec enforces:

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

None of the pods need Kubernetes API access. `automountServiceAccountToken: false` removes an auto-mounted credential from every pod that has no use for it.

The `vulnops` namespace enforces Pod Security Standards at `baseline` with audit and warn set to `restricted`. Not fully restricted only because PostgreSQL `initdb` requires `CAP_CHOWN` to set ownership on its data directory. Frontend and backend pods enforce restricted-equivalent controls through their own pod specs regardless.

Application-layer controls on the Express API:
- `helmet()` adds CSP, `X-Frame-Options`, `Strict-Transport-Security`, and seven other security headers on every response.
- CORS locked to an explicit `ALLOWED_ORIGINS` allowlist; 403 on disallowed origins.
- Rate limiting: global (200/15 min) + stricter write limit (30/15 min on POST/PUT/DELETE).
- Input validation at the API layer — CVE IDs match `CVE-YYYY-NNNNN`, severity/status enum-checked, CVSS score bounded 0–10, field length caps on all text inputs.

</details>

### 6. Audit & detection

Multi-region CloudTrail with SHA-256 digest chain, VPC Flow Logs to S3, all five EKS control-plane log types enabled, and IAM Access Analyzer at account scope. Zero findings is the steady state.

<details>
<summary>Read more</summary>

**CloudTrail:** multi-region trail with log file validation. SHA-256 digest files are generated per delivery; any deleted or modified log breaks the chain. `include_global_service_events = true` ensures IAM and STS events (which always log to us-east-1 regardless of your resource region) are captured.

**VPC Flow Logs:** captures all traffic (ACCEPT and REJECT) and ships to S3. Custom format adds pre-NAT source addresses, TCP flags, subnet ID, and VPC ID for forensic reconstruction. S3 delivery is free at ingest; CloudWatch Logs would charge $0.50/GB.

**EKS control plane logs:** all five types enabled (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`). Everything that talks to the API server is logged.

**Security logs bucket:** public access fully blocked, AES256 encryption, versioning enabled, 30-day transition to STANDARD_IA, 90-day expiration. `force_destroy = true` so the bucket empties cleanly on `terraform destroy` without a manual cleanup step.

**IAM Access Analyzer:** account-scope analyzer continuously evaluates resource-based policies and flags anything accessible from outside the AWS account.

</details>

---

## CI/CD security gates

10 stages, triggered on every push and pull request to `main`. A failure in any gate stops the deployment.

| # | Stage | Tool | What it catches |
|---|---|---|---|
| 1 | Secret scan | Gitleaks | Credentials and tokens in git history. Runs first — no point building if secrets are already exposed. |
| 2 | Lint | ESLint | Backend and frontend in parallel. |
| 3 | Dependency audit | npm audit | Fails on CRITICAL severity findings in third-party packages. |
| 4 | SAST source scan | Semgrep | Scans with `p/nodejs`, `p/owasp-top-ten`, `p/javascript`. SARIF results uploaded to GitHub Security tab. |
| 5 | SAST gate test | Semgrep | Runs `--error` against intentionally insecure fixture. Inverted exit code — if Semgrep finds nothing, the build fails. Validates the ruleset actually fires. |
| 6 | Build + push | Docker Buildx / GHCR | Commit-SHA tagged images with SBOM and SLSA provenance attached. `GITHUB_TOKEN` auth, no stored PATs. |
| 7 | Image scan | Trivy | OS and library CVEs across both images. |
| 8 | IaC scan | Checkov | Misconfigurations in `terraform/` and `k8s/` manifests. |
| 9 | Dockerfile lint | Hadolint | Fails on errors, warns on warnings. |
| 10 | Manifest update | git | Bumps image tags in deployment manifests. ArgoCD picks up the commit and reconciles. |

Every running image is traceable to the exact commit that built it. `latest` is mutable and leaves no audit trail, so it is never used.

---

## Walkthrough

> **Video walkthrough — coming soon.** A 2-minute screen recording will land here once recorded.

In the meantime, every security control is independently verifiable from the command line. See [`walkthrough.md`](walkthrough.md) for the full 7-section proof script. A taste:

```bash
# Pods run as non-root with zero Linux capabilities
kubectl exec -n vulnops deploy/vulnops-backend -- cat /proc/1/status | grep CapEff
# → CapEff: 0000000000000000

# ESO service account has NO AWS credentials — Pod Identity is the auth path
kubectl get sa external-secrets -n external-secrets -o yaml | grep role-arn
# → no output confirms Pod Identity, not IRSA

# IAM Access Analyzer — zero findings means nothing exposed outside the account
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:ACCOUNT:analyzer/vulnops-access-analyzer

# CloudTrail log-file validation chain is intact
aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-1:ACCOUNT:trail/vulnops \
  --start-time $(date -u -d '1 hour ago' +%FT%TZ)
```

Each command in `walkthrough.md` is annotated with the expected output, so a reviewer can run it against a live cluster and verify posture directly.

---

## Running locally

<details>
<summary><b>Docker Compose (recommended)</b></summary>

```bash
docker compose up --build
```

Frontend at `http://localhost`. API at `http://localhost:5000`. Database tables are created on first start.

```bash
docker compose down -v   # teardown and drop volumes
```

</details>

<details>
<summary><b>Without Docker (Node.js 20+ and PostgreSQL)</b></summary>

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

</details>

---

## Deploying to AWS

**Prerequisites:** AWS CLI configured, Terraform ≥ 1.5, kubectl, Helm 3.

First-time AWS setup (IAM user, policies, CLI config): see **[SETUP.md](SETUP.md)**.

### Quick start (automated)

Three commands, ~10 minutes from zero to live cluster with the app deployed.

```bash
# 1. Bootstrap Terraform state backend (once, never destroyed)
./scripts/bootstrap-state.sh

# 2. Provision infrastructure
cd terraform && cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars and set alert_email
terraform init && terraform apply -var-file=terraform.tfvars
aws eks update-kubeconfig --region us-east-1 --name vulnops-eks

# 3. Bootstrap cluster tooling (ESO, ArgoCD, CORS injection)
cd .. && ./scripts/bootstrap-cluster.sh
```

The script prints the frontend URL when done. Click the SNS confirmation email that AWS sends to the address in `terraform.tfvars`, or the cost and TTL alerts won't deliver. From this point forward, any push to `main` triggers a deployment via ArgoCD.

### Full walkthrough (manual)

The same deployment broken into individually-runnable steps, each explaining what it does and why.

<details>
<summary><b>Step 0 — Bootstrap the Terraform state backend</b></summary>

Terraform stores its state in an S3 bucket and uses DynamoDB for state locking. These need to exist before `terraform init` can run, and they sit outside the main stack on purpose — they should survive every `terraform destroy`.

```bash
chmod +x scripts/bootstrap-state.sh
./scripts/bootstrap-state.sh
```

Creates `vulnops-terraform-state` (versioned, AES256 encrypted, public access blocked) and `vulnops-tf-lock` (pay-per-request DynamoDB table). Combined cost at this scale is under $0.01/month. Do not destroy them.

</details>

<details>
<summary><b>Step 1 — Provision infrastructure with Terraform</b></summary>

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars — set alert_email
terraform init
terraform apply -var-file=terraform.tfvars
```

Creates: VPC (3 AZs), EKS cluster (Auto Mode, v1.32, KMS-encrypted secrets), CloudTrail trail, VPC Flow Logs, IAM Access Analyzer, security logs bucket, Secrets Manager entry for the DB credentials, cost guard (Budgets + TTL Lambda + SNS).

</details>

<details>
<summary><b>Step 2 — Configure kubectl</b></summary>

```bash
aws eks update-kubeconfig --region us-east-1 --name vulnops-eks
kubectl get nodes
```

</details>

<details>
<summary><b>Step 3 — Install External Secrets Operator</b></summary>

ESO authenticates to AWS through Pod Identity (set up in Terraform) and syncs secrets from AWS Secrets Manager into Kubernetes.

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace \
  --values bootstrap/external-secrets/helm-values.yaml --wait
```

</details>

<details>
<summary><b>Step 4 — Configure ESO to pull from Secrets Manager</b></summary>

```bash
kubectl apply -f bootstrap/external-secrets/cluster-secret-store.yaml
kubectl create namespace vulnops --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f bootstrap/external-secrets/external-secret.yaml

# Wait for the database secret to materialize
kubectl wait externalsecret/vulnops-db-secret -n vulnops --for=condition=Ready --timeout=60s
```

The `ClusterSecretStore` is scoped to a single secret ARN — the IAM role can read exactly one secret, no wildcards. See `bootstrap/external-secrets/README.md` for rotation instructions.

</details>

<details>
<summary><b>Step 5 — Install ArgoCD and deploy the app</b></summary>

```bash
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl create -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml \
  --save-config 2>/dev/null || true
kubectl wait --for=condition=available --timeout=120s deployment/argocd-server -n argocd

kubectl apply -f k8s/argocd/application.yaml
```

ArgoCD reconciles `k8s/` from git. `selfHeal: true` reverts manual `kubectl apply` drift automatically.

</details>

<details>
<summary><b>Step 6 — Inject the NLB hostname into the backend CORS allowlist</b></summary>

The Express CORS policy is pinned to `ALLOWED_ORIGINS`. The NLB hostname only exists after AWS provisions it, so it's injected after the fact.

```bash
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

<details>
<summary><b>Step 7 — Confirm the SNS alert subscription</b></summary>

AWS sends a confirmation email to the address in `terraform.tfvars` immediately after `terraform apply`. Click the confirmation link or the cost and TTL alerts will not deliver.

</details>

### Verifying the deployment

```bash
# All 5 pods Running
kubectl get pods -n vulnops

# Database secret synced from Secrets Manager
kubectl get externalsecret -n vulnops
# → STATUS=SecretSynced, READY=True

# ESO uses Pod Identity, not IRSA
kubectl get sa external-secrets -n external-secrets -o yaml | grep role-arn
# → no output (no IRSA annotation) confirms Pod Identity
```

Full verification runbook is in [`walkthrough.md`](walkthrough.md) — 7 sections covering secrets, pod hardening, audit trail, IAM posture, cost controls, CI/CD gates, and end-to-end smoke test.

---

## Tearing down

```bash
cd terraform
terraform destroy -var-file=terraform.tfvars
```

Removes the EKS cluster, VPC, NAT gateway, security logs bucket, CloudTrail, Flow Logs, and Access Analyzer. When the cluster is destroyed, all in-cluster resources (ArgoCD, ESO, pods, namespaces) go with it — no manual `kubectl delete`.

The security logs bucket has `force_destroy = true` so Terraform empties versioned CloudTrail and Flow Log objects before deleting.

The Terraform state bucket and DynamoDB lock table persist across destroy cycles by design. Do not delete them.

---

## AI disclosure

**[Claude Code](https://claude.ai/code)** served as an agentic pair-programming assistant throughout all phases. Architecture, security design, and technical decision-making were led and owned by me. Claude handled implementation: writing and refactoring code, executing commands, and generating documentation under direction.

Tools and plugins used:

| Tool | Role |
|---|---|
| **Claude Code** | Agentic CLI — code generation, refactoring, shell execution, and implementation across all phases |
| **Superpowers plugin** | Structured skill workflows for brainstorming, planning, execution, and code review |
| **claude-mem plugin** | Cross-session persistent memory — project context and decisions carried forward between sessions |
| **Notion MCP** | Project notetaker — phase progress, security decisions, and session notes synced to Notion |

---

## Repository structure

```
VulnOps/
├── backend/               # Express API and database schema
├── frontend/              # React + Vite + nginx.conf
├── k8s/
│   ├── namespace.yaml
│   ├── secrets.yaml.example
│   ├── postgres/
│   ├── backend/
│   ├── frontend/
│   ├── network-policies/
│   └── argocd/
├── bootstrap/
│   └── external-secrets/  # ESO install runbook and manifests
├── terraform/             # VPC, EKS, cost guard, security monitoring
├── scripts/
│   ├── bootstrap-state.sh     # Creates S3 state bucket and DynamoDB lock table
│   └── bootstrap-cluster.sh   # Installs ESO and ArgoCD after terraform apply
├── .github/workflows/     # GitHub Actions CI pipeline
├── deploy/                # EC2 setup script for manual deployment
├── docker-compose.yml
├── walkthrough.md         # 7-section security verification runbook
└── VulnOps-Architecture.png
```
