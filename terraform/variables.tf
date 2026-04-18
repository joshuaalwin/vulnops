variable "aws_region" {
  description = "AWS region to deploy the EKS cluster"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "vulnops-eks"
}

variable "cluster_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.32"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "alert_email" {
  description = "Email address for cost and TTL alert notifications"
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly spend threshold in USD — alert fires when actual spend exceeds this"
  type        = number
  default     = 10
}

variable "cluster_ttl_minutes" {
  description = "Alert if the EKS cluster has been running longer than this many minutes"
  type        = number
  default     = 30
}
