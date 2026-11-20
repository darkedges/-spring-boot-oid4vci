mock_provider "pingfederate" {}

variables {
  admin_url               = "https://admin.example.com:9999"
  product_version         = "12.3"
  access_token_manager_id = "existing-atm"
  subject_attribute       = "directory_id"
  roles_attribute         = "groups"
  client_secret           = "test-only-client-secret-at-least-32-characters"
}

run "bank_client_and_claims" {
  command = plan
  assert {
    condition     = pingfederate_oauth_client.bank_hr.client_auth.type == "SECRET"
    error_message = "HR must be a confidential client."
  }
  assert {
    condition     = pingfederate_oauth_client.bank_hr.redirect_uris == toset(["https://hr.bank.darkedges.com/login/oauth2/code/hr"])
    error_message = "The callback must match the bank's Spring Security registration."
  }
  assert {
    condition     = pingfederate_oauth_client.bank_hr.grant_types == toset(["AUTHORIZATION_CODE"])
    error_message = "Only the authorization-code grant is needed."
  }
  assert {
    condition     = pingfederate_oauth_client.bank_hr.restrict_scopes && pingfederate_oauth_client.bank_hr.restricted_scopes == toset(["openid", "profile"])
    error_message = "The bank must be limited to its requested scopes."
  }
  assert {
    condition     = one(pingfederate_openid_connect_policy.bank_hr.attribute_contract.extended_attributes).multi_valued
    error_message = "The bank requires roles to be a JSON array."
  }
  assert {
    condition     = pingfederate_openid_connect_policy.bank_hr.attribute_mapping.attribute_contract_fulfillment["roles"].source.type == "TOKEN"
    error_message = "Roles must originate from authenticated token data, not an unconditional HR grant."
  }
  assert {
    condition     = pingfederate_openid_connect_policy.bank_hr.include_user_info_in_id_token && pingfederate_openid_connect_policy.bank_hr.scope_attribute_mappings["profile"].values == toset(["roles"])
    error_message = "Roles must be released under profile and included through the policy-wide ID-token setting."
  }
}
run "reject_remote_cleartext_callback" {
  command = plan
  variables { bank_base_url = "http://bank.example.com" }
  expect_failures = [var.bank_base_url]
}

run "reject_short_client_secret" {
  command = plan
  variables { client_secret = "short" }
  expect_failures = [var.client_secret]
}

run "explicit_local_development_callback" {
  command = plan
  variables { bank_base_url = "http://localhost:8094" }
  assert {
    condition     = pingfederate_oauth_client.bank_hr.redirect_uris == toset(["http://localhost:8094/login/oauth2/code/hr"])
    error_message = "An explicit local override must still use the exact local callback."
  }
}
