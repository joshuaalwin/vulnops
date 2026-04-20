# AWS account setup

Do this once before running `terraform apply`. Takes about 10 minutes.

Tools needed: AWS CLI, Terraform >= 1.5, kubectl, Helm 3, git

---

## Step 1: Create the IAM user

Use a dedicated IAM user for Terraform, not your root account.

1. Sign in to the [AWS IAM console](https://console.aws.amazon.com/iam)
2. Go to **Users > Create user**
   - Username: `vulnops-admin`
   - Access type: Programmatic access (access key only, no console login)
3. Attach these 10 managed policies on the permissions screen:

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

AWS caps managed policies at 10 per user. These 10 are exactly what's needed.

4. Add two inline policies (JSON tab under the user > Add permissions > Create inline policy):

**`EKSFullAccess`**

AWS has no managed policy for EKS admin operations, so this has to be inline.

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

**`vulnops-bootstrap-extras`**

Covers Secrets Manager (Anthropic key and DB credentials) and IAM Access Analyzer tagging.

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

5. Go to the user's Security credentials tab, create an access key, select CLI, and copy the Access Key ID and Secret Access Key. You won't see the secret again.

---

## Step 2: Configure the AWS CLI

```bash
aws configure --profile vulnops-admin
```

Set region to `us-east-1` and output format to `json`.

Verify it works:

```bash
aws sts get-caller-identity --profile vulnops-admin
# Should return your account ID and arn: .../vulnops-admin
```

Set it as the default profile so you don't need `--profile` on every command:

```bash
export AWS_PROFILE=vulnops-admin
```

Add that to `~/.zshrc` or `~/.bashrc` to make it stick across sessions.

---

## Step 3: Bootstrap the Terraform state backend

Terraform needs an S3 bucket for state and a DynamoDB table for locking before `terraform init` can run. Terraform can't create its own backend, so this script handles the chicken-and-egg problem:

```bash
./scripts/bootstrap-state.sh
```

Creates:
- S3 bucket `vulnops-terraform-state` (versioned, AES256 encrypted, public access blocked)
- DynamoDB table `vulnops-tf-lock` (PAY_PER_REQUEST billing)

These survive `terraform destroy` by design. Don't delete them.

---

## Step 4: Configure terraform.tfvars

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Set `alert_email` to an address you actually check. AWS sends a confirmation email when the stack comes up. If you don't click it, the cost and TTL alerts won't fire.

---

## Ready to deploy

```bash
# Already done in Step 3
./scripts/bootstrap-state.sh

# Provision infrastructure (~8 minutes)
cd terraform && terraform init && terraform apply -var-file=terraform.tfvars
aws eks update-kubeconfig --region us-east-1 --name vulnops-eks

# Install cluster tooling and deploy the app
cd .. && ./scripts/bootstrap-cluster.sh
```

The bootstrap script asks for your Anthropic API key on first run (input is hidden). Get one at [console.anthropic.com](https://console.anthropic.com). To skip the prompt:

```bash
USE_ENV=1 ANTHROPIC_API_KEY=sk-ant-... ./scripts/bootstrap-cluster.sh
```

The script prints the frontend URL when it finishes.

---

## A note on these IAM permissions

`IAMFullAccess` is the uncomfortable one. A principal with that policy can create a new admin role and assume it, which is essentially full account access through a back door. In production you'd replace it with a custom policy listing exactly what Terraform needs. Here it stays because the alternative is spending a day chasing `AccessDenied` errors as you discover each missing action one by one. This is a single isolated account for a portfolio project, and the tradeoff is accepted.

The runtime permissions are tighter. The ESO Pod Identity role can read two Secrets Manager ARNs. The EBS CSI role has storage permissions only. No application pod has static AWS credentials anywhere.
