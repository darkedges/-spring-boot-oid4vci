variable "admin_url" {
  description = "PingFederate admin API origin, e.g. https://pf-admin.example.com:9999. Not the public OIDC discovery URL."
  type        = string
  validation {
    condition     = can(regex("^https://[^/?#]+$", var.admin_url))
    error_message = "Use an HTTPS admin origin without a path or trailing slash."
  }
}
variable "product_version" {
  description = "Actual PingFederate server version. Provider 1.12.0 supports 12.2 through 13.1."
  type        = string
  validation {
    condition     = can(regex("^(12\\.[23]|13\\.[01])(\\.[0-9]+)*$", var.product_version))
    error_message = "This provider supports PingFederate 12.2, 12.3, 13.0 or 13.1; use the installed version."
  }
}
variable "access_token_manager_id" {
  description = "Existing access-token-manager ID used by the functioning OIDC authentication flow."
  type        = string
  validation {
    condition     = length(trimspace(var.access_token_manager_id)) > 0
    error_message = "An existing access-token-manager ID is required."
  }
}
variable "subject_attribute" {
  description = "Existing access-token contract attribute holding the stable authenticated user ID. Maps to OIDC sub."
  type        = string
  validation {
    condition     = length(trimspace(var.subject_attribute)) > 0
    error_message = "Specify the existing access-token subject attribute."
  }
}
variable "roles_attribute" {
  description = "Existing authenticated access-token contract attribute containing roles/groups. HR users must have the exact value bank-hr."
  type        = string
  validation {
    condition     = length(trimspace(var.roles_attribute)) > 0
    error_message = "Specify the existing authenticated role/group token attribute."
  }
}
variable "client_id" {
  description = "Unique client ID for the bank HR application."
  type        = string
  default     = "example-bank-hr"
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.client_id))
    error_message = "Use a non-empty client ID containing letters, numbers, dots, underscores or hyphens."
  }
}
variable "client_secret" {
  description = "Bank client secret. Supply through TF_VAR_client_secret; also configure BANK_OIDC_CLIENT_SECRET with the same value. Stored in Terraform state."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.client_secret) >= 32
    error_message = "Use a randomly generated client secret of at least 32 characters."
  }
}
variable "bank_base_url" {
  description = "Canonical bank origin. HTTP is supported only for localhost development."
  type        = string
  default     = "https://hr.bank.darkedges.com"
  validation {
    condition     = can(regex("^(https://[^/?#*]+|http://localhost(:[0-9]+)?)$", var.bank_base_url))
    error_message = "Use an HTTPS origin or http://localhost[:port], with no path, wildcard or trailing slash."
  }
}
variable "issuer_url" {
  description = "OIDC discovery issuer value used by the bank application."
  type        = string
  default     = "https://id.ping.darkedges.com"
  validation {
    condition     = can(regex("^https://[^?#]+[^/]$", var.issuer_url))
    error_message = "Use the exact HTTPS issuer without a trailing slash."
  }
}
variable "bank_name" {
  description = "Display name in PingFederate."
  type        = string
  default     = "Risk E Bank"
}
variable "ca_certificate_pem_files" {
  description = "Optional local PEM root CA paths for a private admin API certificate; TLS verification stays enabled."
  type        = set(string)
  default     = null
}
