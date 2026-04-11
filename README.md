# VulnOps

A CVE registry for tracking and managing vulnerabilities. React frontend, Express API, PostgreSQL backend.

## What it does

You report a CVE by giving it an ID, severity, affected product, CVSS score, and a description. VulnOps stores it, lets you update its status as you work through remediation, and attach notes per entry.

## Stack

- **Frontend**: React 18, Vite, React Router
- **Backend**: Node.js, Express
- **Database**: PostgreSQL
- **Reverse proxy**: Nginx
- **Process manager**: PM2 (production)

## Architecture

```
User → Nginx (port 80) → React frontend
                       → Express API (port 5000) → PostgreSQL (port 5432)
```

## Running locally

Node.js 20+ and PostgreSQL required.

**1. Set up the database**

```bash
sudo -u postgres psql <<EOF
CREATE USER vulnops WITH PASSWORD 'vulnops';
CREATE DATABASE vulnops OWNER vulnops;
GRANT ALL PRIVILEGES ON DATABASE vulnops TO vulnops;
\c vulnops
GRANT ALL ON SCHEMA public TO vulnops;
EOF
```

**2. Start everything**

```bash
cd VulnOps
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`, API at `http://localhost:5000`. Database tables are created automatically on first backend start.

## Project structure

```
VulnOps/
├── backend/      # Express API + DB logic
├── frontend/     # React + Vite
├── deploy/       # EC2 setup script + Nginx config
└── package.json  # Runs both servers via concurrently
```

## Milestones

Building this out as a full DevSecOps implementation, not just "app on a server."

**Done**
- [x] Three-tier application (React + Express + PostgreSQL)
- [x] Manual EC2 deployment with Nginx and PM2

**Up next**
- [ ] **Terraform**: Provision a VPC and EKS cluster on AWS using official Terraform modules. No manual console work.
- [ ] **Docker**: Containerize frontend and backend. Verify locally with Docker Compose before moving to Kubernetes.
- [ ] **Kubernetes manifests**: One manifest covering Deployments, Services, NetworkPolicies, and storage. `kubectl apply` and the whole app is up.
- [ ] **CI/CD (GitHub Actions)**: Every commit triggers a build, pushes images to GHCR, updates K8s manifests, and deploys to EKS automatically.
- [ ] **Security scanning**: Trivy for container image CVEs, Checkov for Terraform and Kubernetes manifest scanning. Both run in CI and block on failure.

## Deploying to EC2

```bash
git clone https://github.com/<your-username>/vulnops.git ~/VulnOps
cd ~/VulnOps/deploy
chmod 700 setup.sh
./setup.sh
```

Installs Node.js, PostgreSQL, Nginx, and PM2, then starts the app on port 80. Make sure port 80 is open in your EC2 security group first.
