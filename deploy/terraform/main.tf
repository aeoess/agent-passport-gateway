# In-tenant AEOESS gateway - Terraform module (G-D4).
#
# Provisions the customer-owned pieces the gateway depends on:
#   - a customer KMS key for the tenant signing root (customer brings their
#     own trust root; the gateway only ever holds a reference to this key,
#     never the private material),
#   - a persistent volume claim for hash-and-pointer storage,
#   - a Helm release of the in-tenant chart with isolation-by-default.
#
# This runs in the CUSTOMER's cloud account. AEOESS does not hold the key,
# the data, or the cluster. THIN-GATEWAY: authority lives at the customer edge.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12"
    }
  }
}

variable "tenant_name" {
  type        = string
  description = "Customer tenant name; used to label the KMS key and release."
}

variable "isolation_mode" {
  type        = string
  default     = "hard"
  description = "D2 isolation switch. 'hard' (regulated, default-safe) or 'standard'."
  validation {
    condition     = contains(["hard", "standard"], var.isolation_mode)
    error_message = "isolation_mode must be 'hard' or 'standard'."
  }
}

variable "namespace" {
  type    = string
  default = "aeoess"
}

variable "chart_path" {
  type        = string
  default     = "../helm/aeoess-gateway"
  description = "Path to the in-tenant Helm chart."
}

# Customer-owned KMS key: the tenant signing root. The gateway is granted only
# a reference (the key ARN), never the key material. Key rotation is enabled
# so a root rotation can cascade-revoke stale automations downstream.
resource "aws_kms_key" "tenant_trust_root" {
  description             = "AEOESS in-tenant signing root for ${var.tenant_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = {
    tenant = var.tenant_name
    role   = "aeoess-trust-root"
  }
}

resource "aws_kms_alias" "tenant_trust_root" {
  name          = "alias/aeoess-${var.tenant_name}-trust-root"
  target_key_id = aws_kms_key.tenant_trust_root.key_id
}

# Helm release of the in-tenant gateway. isolation_mode and the KMS key
# reference are threaded through. For a regulated tenant, denyEgress can be
# set true to block all outbound traffic at the network layer.
resource "helm_release" "gateway" {
  name             = "aeoess-${var.tenant_name}"
  chart            = var.chart_path
  namespace        = var.namespace
  create_namespace = true

  set {
    name  = "isolation.mode"
    value = var.isolation_mode
  }

  set {
    name  = "trustRoot.source"
    value = "kms"
  }

  # Opaque reference to the customer KMS key. NEVER the private key material.
  set {
    name  = "env.TRUST_ROOT_KEY_REF"
    value = aws_kms_key.tenant_trust_root.arn
  }

  # Regulated tenant: block egress at the network layer too.
  set {
    name  = "network.denyEgress"
    value = var.isolation_mode == "hard" ? "true" : "false"
  }
}

output "trust_root_key_arn" {
  value       = aws_kms_key.tenant_trust_root.arn
  description = "Customer-owned KMS key ARN. Passed to the gateway as a reference only."
}

output "isolation_mode" {
  value = var.isolation_mode
}
