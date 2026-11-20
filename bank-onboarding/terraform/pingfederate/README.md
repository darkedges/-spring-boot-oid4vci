# Bank HR client in PingFederate

Terraform project for step 1 of the bank setup: a confidential authorization-code client and a dedicated OIDC policy that emits a multi-valued `roles` claim. It uses the official `pingidentity/pingfederate` provider pinned to 1.12.0, which supports PingFederate 12.2 through 13.1. Supply your actual server version; an older server needs a compatible provider version and revalidation.

The project reuses your existing authentication flow and access-token manager. It does not replace a shared policy, create users, change global scopes, or grant all authenticated users HR access. No remote changes were applied during project generation.

## Inputs to obtain from your existing server

In the PingFederate admin console identify:

| Input | Where / meaning |
| --- | --- |
| `admin_url` | HTTPS origin of the admin management API, typically on port 9999 or a separate admin hostname. The public discovery URL does not identify it. |
| `product_version` | Actual PingFederate server version. |
| `access_token_manager_id` | ID of the functioning access-token manager under Applications > OAuth > Access Token Management. Use its ID, not its display name. |
| `subject_attribute` | Access-token contract attribute holding a stable authenticated user ID; inspect the existing working OIDC policy's `sub` fulfillment. |
| `roles_attribute` | Access-token contract attribute holding authenticated roles or group values. It must actually be populated by the existing authentication/token mappings. |

If HR membership is currently in `groups`, set `roles_attribute` to that token contract attribute. Authorized HR users must have the exact value `bank-hr`. A value such as `CN=Bank HR,OU=Groups,...` does not match. Either supply an existing attribute containing `bank-hr`, or configure a dedicated, authenticated upstream mapping that transforms the selected HR group to `bank-hr` before running the client. Directory group creation and membership assignment depend on your directory and are not managed by this project.

The OIDC discovery document advertising `groups` does not prove that a particular access-token manager has a `groups` contract attribute. Verify the actual contract and its mapping. Use the same stable subject mapping as your existing OIDC clients. Never populate roles from a request parameter or a constant granting `bank-hr` to everyone.

## Run in PowerShell 7

From this directory:

```powershell
Copy-Item terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars and replace all environment-specific placeholder values.
notepad terraform.tfvars

# Admin API credentials, separate from the new application's client credentials.
$env:PINGFEDERATE_PROVIDER_USERNAME = Read-Host 'PingFederate admin API username'
$adminPassword = Read-Host 'PingFederate admin API password' -AsSecureString
$env:PINGFEDERATE_PROVIDER_PASSWORD = [System.Net.NetworkCredential]::new('', $adminPassword).Password

# Generate the application client secret once. Keep the same value for later runs.
# If BANK_OIDC_CLIENT_SECRET already contains the intended secret, reuse it instead.
if (-not $env:BANK_OIDC_CLIENT_SECRET) {
    $secretBytes = [byte[]]::new(48)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($secretBytes)
    $env:BANK_OIDC_CLIENT_SECRET = [Convert]::ToBase64String($secretBytes)
}
$env:TF_VAR_client_secret = $env:BANK_OIDC_CLIENT_SECRET

terraform init
terraform fmt -check -recursive
terraform validate
terraform test
terraform plan -out=bank-hr.tfplan
# Review the plan, then run it:
terraform apply bank-hr.tfplan

$env:BANK_OIDC_CLIENT_ID = terraform output -raw client_id
$bankSettings = terraform output -json bank_environment | ConvertFrom-Json
$env:BANK_OIDC_ISSUER = $bankSettings.BANK_OIDC_ISSUER
$env:BANK_BASE_URL = $bankSettings.BANK_BASE_URL
```

The defaults register `example-bank-hr` with callback `https://hr.bank.darkedges.com/login/oauth2/code/hr`, requesting `openid profile`. The roles claim is released under `profile`, matching the bank's existing configuration. The client authenticates with a secret; the bank uses Spring Security's confidential authorization-code login. Refresh-token, implicit and client-credentials grants are not enabled for this application.

Save the generated application secret in your local secret store before closing the shell. On subsequent Terraform runs set `TF_VAR_client_secret` and the bank's `BANK_OIDC_CLIENT_SECRET` to that same saved value. Generating another value rotates the configured client secret when applied.

Keep Terraform state, saved plans, and tfvars private: sensitive marking redacts CLI output but does not encrypt state. The local ignore file excludes these files. Commit `.terraform.lock.hcl`. Use an encrypted, access-controlled remote backend if sharing state with others.

Provider authentication can alternatively use the provider's documented access-token or OAuth environment variables. Do not leave multiple authentication methods set at once. TLS verification remains enabled. For a private admin CA set `ca_certificate_pem_files` to trusted PEM files.

The current canonical origin is `https://hr.bank.darkedges.com`. Apply the updated `bank_base_url` input before restarting the bank so its Terraform-derived environment and registered callback agree. Configure the Cloudflare Tunnel route separately as described in the parent README.

## Verify login

Start the bank application in the same shell after supplying its database and key settings from the parent README. Open `https://hr.bank.darkedges.com/hr`.

- An authenticated HR user must receive `roles: ["bank-hr"]` (possibly with other values) and access the HR page.
- An ordinary authenticated user without `bank-hr` must receive HTTP 403 for `/hr`.
- A missing claim or a scalar `roles: "bank-hr"` must not grant HR access. This OIDC policy sets `multi_valued = true` to ensure array serialization.

The dedicated policy maps roles from authenticated token data and always includes it in the ID token. It maps the stable subject from the selected access-token attribute. Verify the emitted claims locally; do not paste tokens into external debugging sites.

If the existing token manager restricts allowed clients, its owner must allow this client. If your authentication policy routes by client ID, enable the appropriate route for `example-bank-hr`. This project deliberately does not take ownership of those shared configurations.

## Existing resources and troubleshooting

For a new client ID the plan should create exactly two resources. Choose another `client_id` if the default already belongs to another application. To intentionally adopt an existing matching client or policy, review its configuration first and import it with the documented IDs; subsequent plans can change imported configuration.

```powershell
terraform import pingfederate_openid_connect_policy.bank_hr example-bank-hr-oidc
terraform import pingfederate_oauth_client.bank_hr example-bank-hr
terraform plan
```

A 401 or 403 from the admin API concerns provider credentials/permissions or your admin proxy. It is distinct from a successfully authenticated bank user receiving 403 because they lack `bank-hr`. A claim-mapping error generally means the selected access-token contract does not contain/populate the requested attributes. An admin TLS failure should be resolved with the correct hostname and CA trust.

`terraform destroy` removes the two managed resources and disables bank HR login; it does not remove upstream users or group assignments. No automatic cluster replication is configured; follow your existing PingFederate deployment/replication process after applying if your topology requires it.

### Inconsistent result for per-claim inclusion flags

The live server returned `null` for `include_in_id_token` and `include_in_user_info` after they had been explicitly set to `true`. This produced an inconsistent-result error on the set of extended attributes even though the policy was created. Those per-claim flags are now omitted. The configuration retains `multi_valued = true`, releases roles under `profile`, and sets policy-wide `include_user_info_in_id_token = true`. Verify the actual roles claim in the first live login.

For the observed failure, `darkedges-bank-hr-oidc` is already recorded in local state. Generate a fresh plan after this correction, then apply it. Do not reuse the previous saved plan, delete the policy, or import it again. If working with another state/backend, check `terraform state list` before deciding whether an import is needed.

## Validation performed

`terraform init -backend=false`, `terraform fmt -check -recursive`, `terraform validate`, and four mocked-provider `terraform test` runs passed. Tests verify the client grant, exact callback, scope restriction, array role mapping, rejection of remote cleartext origins, and secret length. Mocked tests do not contact the admin API or validate live token contents. A live plan/apply awaits your admin origin, version, token-manager ID, mapping attributes, and credentials.

## Official references

- [Provider and authentication](https://registry.terraform.io/providers/pingidentity/pingfederate/1.12.0/docs)
- [OAuth client resource](https://registry.terraform.io/providers/pingidentity/pingfederate/1.12.0/docs/resources/oauth_client)
- [OIDC policy resource](https://registry.terraform.io/providers/pingidentity/pingfederate/1.12.0/docs/resources/openid_connect_policy)
- [Preparing PingFederate for Terraform](https://terraform.pingidentity.com/getting-started/pingfederate/)
