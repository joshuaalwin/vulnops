# ==============================================================
# VulnOps EKS Cluster - Auto Mode
# ==============================================================

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 3)
}

# ---- VPC ----
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 48)]

  enable_nat_gateway = true
  single_nat_gateway = true # Cost-saving for dev; use one per AZ in prod

  # Tags required for EKS Auto Mode to discover subnets
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

# ---- EKS Cluster (Auto Mode) ----
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  # Auto Mode — EKS manages node groups, kube-proxy, CoreDNS, etc.
  cluster_compute_config = {
    enabled    = true
    node_pools = ["general-purpose", "system"]
  }

  # Networking — nodes in private subnets, not directly internet-reachable
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Security: enable private endpoint; public enabled for initial kubectl access
  # After initial setup, set cluster_endpoint_public_access = false
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  # Auth mode required for Auto Mode
  authentication_mode = "API"

  # Security: envelope encryption for K8s secrets at rest
  cluster_encryption_config = {
    resources = ["secrets"]
  }

  # Security: enable all control plane log types for audit trail
  cluster_enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  # Allow current IAM caller (vulnops-terraform user) to manage the cluster
  enable_cluster_creator_admin_permissions = true

  # Security: enable NetworkPolicy enforcement in the VPC CNI plugin.
  # Without this, NetworkPolicy objects exist in the cluster but no controller
  # reads or enforces them — all pod-to-pod traffic flows regardless of policy.
  cluster_addons = {
    vpc-cni = {
      configuration_values = jsonencode({
        enableNetworkPolicy = "true"
      })
    }
  }
}
