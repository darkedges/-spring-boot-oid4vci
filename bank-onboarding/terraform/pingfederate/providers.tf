# Authentication comes from PINGFEDERATE_PROVIDER_* environment variables.
# Keep these credentials distinct from the bank application's client secret.
provider "pingfederate" {
  https_host               = var.admin_url
  product_version          = var.product_version
  admin_api_path           = "/pf-admin-api/v1"
  insecure_trust_all_tls   = false
  ca_certificate_pem_files = var.ca_certificate_pem_files
}
