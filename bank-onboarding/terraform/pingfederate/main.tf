locals {
  redirect_uri = "${var.bank_base_url}/login/oauth2/code/hr"
}

resource "pingfederate_openid_connect_policy" "bank_hr" {
  policy_id = "${var.client_id}-oidc"
  name      = "${var.bank_name} HR"
  access_token_manager_ref = {
    id = var.access_token_manager_id
  }
  attribute_contract = {
    # This server omits per-attribute inclusion flags in its API response.
    # Use include_user_info_in_id_token and scope_attribute_mappings below.
    extended_attributes = [{
      name         = "roles"
      multi_valued = true
    }]
  }
  attribute_mapping = {
    attribute_contract_fulfillment = {
      sub = {
        source = { type = "TOKEN" }
        value  = var.subject_attribute
      }
      roles = {
        source = { type = "TOKEN" }
        value  = var.roles_attribute
      }
    }
  }
  scope_attribute_mappings = {
    profile = { values = ["roles"] }
  }
  include_user_info_in_id_token = true
  id_token_lifetime             = 5
}

resource "pingfederate_oauth_client" "bank_hr" {
  client_id   = var.client_id
  name        = "${var.bank_name} HR portal"
  description = "Staff onboarding administration"
  enabled     = true
  client_auth = {
    type   = "SECRET"
    secret = var.client_secret
  }
  grant_types   = ["AUTHORIZATION_CODE"]
  redirect_uris = [local.redirect_uri]
  default_access_token_manager_ref = {
    id = var.access_token_manager_id
  }
  oidc_policy = {
    policy_group = { id = pingfederate_openid_connect_policy.bank_hr.id }
  }
  restrict_scopes      = true
  restricted_scopes    = ["openid", "profile"]
  bypass_approval_page = false
  # Matches Spring's current confidential-client login configuration.
  require_proof_key_for_code_exchange = false
}
