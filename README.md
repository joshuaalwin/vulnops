# VulnOps

A CVE registry for tracking and managing vulnerabilities — built as a DevSecOps portfolio project demonstrating end-to-end secure infrastructure, containerization, and Kubernetes deployment on AWS.

**Stack:** React + Nginx · Node.js/Express · PostgreSQL  
**Infrastructure:** AWS EKS (Auto Mode) · Terraform · Docker · Kubernetes

---

## What it does

Report a CVE with an ID, severity, affected product, CVSS score, and description. VulnOps stores it, tracks remediation status, and lets you attach notes per entry. The live CVSS v3.1 calculator on the submission form computes scores using the official FIRST formula.

---

## Architecture

```
Internet → AWS NLB → nginx (port 8080, non-root)
                   → React SPA (static assets)
                   → Express API (port 5000, ClusterIP) → PostgreSQL (port 5432, ClusterIP)
```

All three tiers run in Kubernetes on EKS. Backend and database are ClusterIP-only — not reachable from outside the cluster. Only the frontend NLB is internet-facing.

---

## DevSecOps implementation

### Phase 1 — Three-tier app + EC2 ✅
- React frontend, Express API, PostgreSQL
- Manual EC2 deployment via Nginx + PM2 + `setup.sh`
- `npm install --ignore-scripts` to block malicious postinstall hooks (ref: Axios supply chain attack)

### Phase 2 — Infrastructure as Code ✅
- Terraform: VPC + EKS Auto Mode cluster on AWS
- S3 backend for Terraform state (SSE-AES256 + versioned) + DynamoDB state locking
- EKS nodes in private subnets — not directly internet-reachable
- Checkov scan on all Terraform manifests

### Phase 3 — Containerization ✅
- Multi-stage Dockerfiles: non-root user, Alpine base, no dev dependencies in production
- Nginx production image pinned to SHA256 digest — tags are mutable, digests aren't
- Intentionally left `node:20-alpine` build stage unpinned to carry known CVEs for Trivy gate demo in Phase 6
- `docker-compose.yml` for local three-tier stack with healthchecks

### Phase 4 — Kubernetes + EKS deployment ✅
- Full K8s manifest set: Deployments, Services, NetworkPolicies, PVC
- SecurityContext on every pod: `runAsNonRoot`, `readOnlyRootFilesystem`, `drop: [ALL]` capabilities
- Default-deny NetworkPolicy baseline — explicit allows only for required paths
- `automountServiceAccountToken: false` on all pods
- Namespace Pod Security Standards enforced (baseline enforcement, restricted audit/warn)
- gp3 StorageClass with `ebs.csi.eks.amazonaws.com` (EKS Auto Mode CSI provisioner)
- Internet-facing NLB for frontend; backend and DB are ClusterIP-only

### Phase 5 — CI/CD (GitHub Actions + ArgoCD) ✅
- 8-stage pipeline: Gitleaks → ESLint → npm audit → Docker build+push → Trivy → Checkov → Hadolint → manifest update
- Images pushed to GHCR tagged with commit SHA — every running image traceable to the exact commit that built it
- SBOM and build provenance attestation attached to every image automatically via Docker Buildx
- ArgoCD running in EKS — watches git, auto-deploys on manifest changes, reverts manual `kubectl` drift
- CI never holds cluster credentials — ArgoCD pulls from git (GitOps pattern)
- `GITHUB_TOKEN` for GHCR auth — no long-lived PATs stored as secrets

### Phase 6 — Security tooling in CI/CD ⬜
- Tighten Trivy gate: hard fail on CRITICAL (currently `continue-on-error` for Phase 5 demo)
- Tighten Checkov: remove `soft_fail`, gate on findings
- Enable VPC CNI NetworkPolicy controller in EKS for actual policy enforcement
- Upgrade `node:20-alpine` base image once Trivy gate is demonstrated

### Phase 7 — Application security ⬜
- JWT authentication, RBAC (reporter/reviewer/admin)
- Rate limiting, input sanitization, audit log

### Phase 8 — Extended integrations ⬜
- SAST (Semgrep), DAST (OWASP ZAP), Falco, OPA/Kyverno, Cosign image signing
- GuardDuty + CloudTrail, centralized logging

### Phase 9 — AI integration ⬜
- NVD API auto-enrichment on CVE submission
- Claude API for severity triage and remediation suggestions

---

## Running locally

Docker and Docker Compose required.

```bash
docker compose up --build
```

Frontend at `http://localhost`, API at `http://localhost:5000`. Database tables are created automatically on first backend start.

**Without Docker** — Node.js 20+ and PostgreSQL required:

```bash
# Set up the database
sudo -u postgres psql <<EOF
CREATE USER vulnops WITH PASSWORD 'vulnops';
CREATE DATABASE vulnops OWNER vulnops;
GRANT ALL PRIVILEGES ON DATABASE vulnops TO vulnops;
\c vulnops
GRANT ALL ON SCHEMA public TO vulnops;
EOF

# Start frontend + backend together
npm install
npm run dev
```

Frontend at `http://localhost:5173`, API at `http://localhost:5000`.

---

## Repository structure

```
VulnOps/
├── backend/              # Express API + DB schema
├── frontend/             # React + Vite + nginx.conf
├── k8s/                  # Kubernetes manifests
│   ├── namespace.yaml
│   ├── secrets.yaml.example
│   ├── postgres/
│   ├── backend/
│   ├── frontend/
│   ├── network-policies/
│   └── argocd/           # ArgoCD Application CRD
├── terraform/            # VPC + EKS infrastructure
├── .github/workflows/    # GitHub Actions CI pipeline
├── deploy/               # Legacy EC2 setup script
└── docker-compose.yml
```

---

## Key security decisions

| Decision | Rationale |
|---|---|
| `npm install --ignore-scripts` | Blocks postinstall-based supply chain attacks (ref: Axios 1.14.1/0.30.4 RAT) |
| EKS nodes in private subnets | Not internet-reachable. NAT gateway for outbound only. |
| Terraform state in S3 + DynamoDB | State encrypted at rest, versioned, locked against concurrent writes |
| Nginx pinned to SHA256 digest | Image tags are mutable — digest guarantees byte-for-byte identity |
| `drop: [ALL]` capabilities on frontend/backend | Zero Linux capabilities. Limits what an attacker can do post-RCE. |
| `readOnlyRootFilesystem: true` on frontend/backend | Prevents writing webshells or tools post-compromise |
| Default-deny NetworkPolicy | All pod traffic blocked by default. Explicit allows only. |
| `automountServiceAccountToken: false` | No pod needs K8s API access — removes an auto-mounted credential from every pod |
| GHCR over Docker Hub | CI/CD uses built-in `GITHUB_TOKEN` — no stored PATs required |
| Baseline PSS for postgres only | Postgres initdb requires `CAP_CHOWN` to chmod its data directory. Stateless tiers stay restricted. |
| SHA tag over `latest` for images | `latest` is mutable and untraceable. SHA tag ties every running pod to the exact commit that built it. |
| ArgoCD GitOps over `kubectl` from CI | CI never holds cluster credentials. Cluster pulls from git. `selfHeal` enforces git as the only write path to production. |
| SBOM + provenance on every image | Attached to GHCR automatically via BuildKit. Full software supply chain transparency — what's in the image and where it was built. |
