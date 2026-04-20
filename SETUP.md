# AWS Account Setup

Prerequisites before running `terraform apply`. Do this once per AWS account.

**Tools required:** AWS CLI, Terraform ≥ 1.5, kubectl, Helm 3, git

---

## Step 1 — Create the IAM user

VulnOps uses a dedicated IAM user (`vulnops-admin`) for Terraform. Never use your root account credentials.

1. Sign in to the [AWS IAM console](https://console.aws.amazon.com/iam)
2. **Users → Create user**
   - Username: `vulnops-admin`
   - Access type: **Programmatic access** (access key only — no console login needed)
3. On the permissions screen, attach these 10 managed policies:

| Policy name | Why it's needed |
|---|---|
| `AmazonEC2FullAccess` | VPC, subnets, NAT gateway, EKS node resources |
| `AmazonS3FullAccess` | Terraform state bucket |
| `AmazonVPCFullAccess` | VPC, route tables, security groups |
| `IAMFullAccess` | IAM roles Terraform creates for EKS and Pod Identity |
| `AmazonDynamoDBFullAccess` | Terraform state lock table |
| `AWSKeyManagementServicePowerUser` | KMS key for Kubernetes secrets encryption at rest |
| `CloudWatchLogsFullAccess` | EKS control plane audit logs (all 5 log types) |
| `ElasticLoadBalancingFullAccess` | NLB provisioned by the frontend K8s Service |
| `AmazonGuardDutyFullAccess_v2` | GuardDuty threat detection |
| `AWSCloudTrail_FullAccess` | CloudTrail multi-region trail |

> AWS enforces a 10 managed policy limit per user. These 10 are the exact set needed — no room to spare.

4. After creating the user, add **two inline policies** (JSON tab under the user → Add permissions → Create inline policy):

**Inline policy 1 — `EKSFullAccess`**

No AWS managed policy covers EKS admin operations. This inline policy gives Terraform full EKS access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "eks:*",
      "Resource": "*"
    }
  ]
}
```

**Inline policy 2 — `vulnops-bootstrap-extras`**

Needed for Secrets Manager (Anthropic key + DB credentials) and IAM Access Analyzer tagging.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:*",
        "access-analyzer:*"
      ],
      "Resource": "*"
    }
  ]
}
```

5. Go to the user's **Security credentials** tab → **Create access key** → select **CLI** → copy the Access Key ID and Secret Access Key. You won't see the secret again.

---

## Step 2 — Configure the AWS CLI

```bash
aws configure --profile vulnops-admin
```

Enter the access key ID and secret from step 1. Set region to `us-east-1` and output format to `json`.

Verify it works:

```bash
aws sts get-caller-identity --profile vulnops-admin
# Should return your account ID and arn: .../vulnops-admin
```

Set it as the default profile for this project so you don't need `--profile` on every command:

```bash
export AWS_PROFILE=vulnops-admin
```

Add that export to your shell profile (`~/.zshrc` or `~/.bashrc`) or prepend it to every command below.

---

## Step 3 — Bootstrap the Terraform state backend

Terraform stores state in S3 and uses DynamoDB for locking. These must exist before `terraform init` can run — Terraform cannot create its own backend.

```bash
./scripts/bootstrap-state.sh
```

This creates:
- S3 bucket `vulnops-terraform-state` (versioned, AES256 encrypted, public access blocked)
- DynamoDB table `vulnops-tf-lock` (PAY_PER_REQUEST billing)

Both persist across `terraform destroy` cycles by design. **Do not delete them.**

---

## Step 4 — Configure terraform.tfvars

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Open `terraform.tfvars` and set `alert_email` to an email address you control. AWS will send a confirmation email — click it or the cost and TTL alerts won't deliver.

---

## You're ready

Run the three-command deploy from the repo root:

```bash
# Already done in Step 3
./scripts/bootstrap-state.sh

# Provision infrastructure (~8 minutes)
cd terraform && terraform init && terraform apply -var-file=terraform.tfvars
aws eks update-kubeconfig --region us-east-1 --name vulnops-eks

# Install cluster tooling and deploy the app
cd .. && ./scripts/bootstrap-cluster.sh
```

The bootstrap script will prompt for your Anthropic API key on first run (input hidden). Get one at [console.anthropic.com](https://console.anthropic.com). To pass it non-interactively:

```bash
USE_ENV=1 ANTHROPIC_API_KEY=sk-ant-... ./scripts/bootstrap-cluster.sh
```

The script prints the frontend URL when done.

---

## Security note on these IAM permissions

`IAMFullAccess` allows privilege escalation — a principal with this policy can create a new admin role and assume it. In production, Terraform's bootstrap role would be a custom IAM policy scoped to exactly the resource types and actions it needs. The tradeoff here is operational simplicity for a portfolio project where the blast radius is a single isolated AWS account.

The runtime workload permissions are properly scoped: the ESO Pod Identity role can read exactly two Secrets Manager ARNs, the EBS CSI role has only storage permissions, and no application pod has static AWS credentials anywhere.
