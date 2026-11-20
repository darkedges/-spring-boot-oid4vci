output "client_id" {
  description = "Set BANK_OIDC_CLIENT_ID to this value."
  value       = pingfederate_oauth_client.bank_hr.client_id
}
output "redirect_uri" {
  value = local.redirect_uri
}
output "oidc_policy_id" {
  value = pingfederate_openid_connect_policy.bank_hr.id
}
output "bank_environment" {
  description = "Non-secret bank environment settings. Set BANK_OIDC_CLIENT_SECRET separately from the input secret."
  value = {
    BANK_OIDC_CLIENT_ID = pingfederate_oauth_client.bank_hr.client_id
    BANK_OIDC_ISSUER    = var.issuer_url
    BANK_BASE_URL       = var.bank_base_url
  }
}
