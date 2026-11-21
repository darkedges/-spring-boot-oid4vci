# Risk E Bank staff onboarding

This module runs separately on port 8094 and reuses the OID4VCI issuer and OID4VP SD-JWT verifier libraries. HR access uses OIDC; staff access uses a holder-bound staff credential and a current database status check.

## Start with Make

Use GNU Make and PowerShell 7 (`make` and `pwsh` on PATH). From `oid4vci/bank-onboarding`:

```powershell
# Select JDK 21+. This machine has this JDK installed:
$env:JAVA_HOME = 'C:\development\utils\java\jdk25.0.18'
make doctor
make start
```

`make start` reads the applied Terraform `bank_environment` output, prepares missing keys, starts PostgreSQL and waits for its health check, then runs the existing bank JAR in the foreground. For the OIDC secret it first uses `BANK_OIDC_CLIENT_SECRET` from your shell, then the applied client secret from Terraform state, then Terraform evaluation of `client_secret` (including `terraform.tfvars`, auto-loaded tfvars and `TF_VAR_client_secret`). It reads state through `terraform state pull`, supporting the configured backend. Terraform evaluates configuration rather than the helper parsing HCL. `BANK_DATABASE_PASSWORD` is reused from your shell. Any remaining missing secrets are prompted for securely. Enter the existing applied OIDC secret and reuse the database's original password. The helper captures the secret without printing it or writing another secret file. OIDC prompts repeat only if no usable Terraform or environment secret is available; database prompts repeat unless your shell supplies its password. A configured secret that differs from the applied state is not used until applied, unless you explicitly override `BANK_OIDC_CLIENT_SECRET`. Ctrl+C stops the portal; PostgreSQL stays running.

For an explicit localhost-only USB demonstration, in a second terminal in the same directory:

```powershell
make phone
```

Open the printed bank URL with `/hr`. The phone target sets up USB forwarding for `localhost:8094`; use the canonical bank URL registered by Terraform. Install the updated Android wallet/proofing app and deploy the updated proofing backend separately using their project instructions.

Other targets:

| Target              | Action                                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------------------ |
| `make help`         | List commands.                                                                                         |
| `make setup`        | Create missing bank signing key and pin missing passport issuer key.                                   |
| `make keys`         | Create the bank signing key only if absent.                                                            |
| `make passport-key` | Fetch and pin one public ES256/P-256 signing key from the configured issuer's `/jwks`, only if absent. |
| `make db-up`        | Start PostgreSQL and wait for readiness.                                                               |
| `make db-down`      | Stop PostgreSQL, retaining the data volume.                                                            |
| `make run`          | Load settings and run the JAR against an already running database.                                     |
| `make build`        | Install sibling OID4VP dependencies and package the bank reactor with tests.                           |
| `make test`         | Install sibling dependencies and run bank/reactor tests.                                               |

Existing signing and passport trust keys are retained. The default key directory is `%LOCALAPPDATA%/ExampleBank`. For first-time passport key pinning, use your trusted issuer's URL (`PASSPORT_ISSUER`, default `https://issuer.zkp.au`). If the issuer publishes more than one eligible key, set `PASSPORT_KEY_ID` to the intended signing key ID; the helper refuses to pick arbitrarily. You can also install an independently verified public JWK manually at `PASSPORT_PUBLIC_JWK_FILE` before running setup.

Optional environment overrides: `BANK_JAVA` (Java executable), `BANK_MVN`, `BANK_MAVEN_REPO`, `BANK_ADB`, `BANK_SECRET_DIR`, `BANK_PRIVATE_JWK_FILE`, `PASSPORT_PUBLIC_JWK_FILE`, `BANK_TERRAFORM_DIR`, and `BANK_JAR`. ADB is found via PATH, `ANDROID_HOME`, `ANDROID_SDK_ROOT`, or the usual local Android SDK directory. Override the PowerShell command with `make PWSH=pwsh.exe help` if needed. Build selects the same JDK for Maven and the portal.

Use `make build` if the packaged JAR is missing or sources have changed. `make start` does not rebuild, apply Terraform, or redeploy the mobile apps. Settings loaded inside Make apply to that process and its children; they do not modify the calling shell.

### Docker address pool exhaustion

The database uses an explicit subnet, `10.243.0.0/24`, to avoid consuming Docker's exhausted automatic address pools on this development machine. That subnet was checked against the existing Docker network list and Windows IPv4 routes. If another machine uses it already, choose a free, non-overlapping private subnet before startup:

```powershell
$env:BANK_DOCKER_SUBNET = '10.244.0.0/24' # example; verify it is free on your machine
make start
```

An address pool exhaustion error does not require deleting the PostgreSQL volume. The Compose configuration supports subnet overrides through its [IPAM network settings](https://docs.docker.com/reference/compose-file/networks/#ipam).

### Database host port

PostgreSQL is published on `127.0.0.1:15432`; it still listens on 5432 inside its container. Port 5432 on this development machine belongs to another application's database. `make start` and `make run` supply `jdbc:postgresql://localhost:15432/bank` to the existing packaged JAR automatically, so this port change does not require a rebuild.

Set `BANK_DATABASE_PORT` in the calling shell to use another free host port. Compose and the helper's generated JDBC URL both use it. An explicit `BANK_DATABASE_URL` overrides the generated URL; update or clear an old URL pointing to port 5432 before starting the bank. Re-running `make start` recreates the bank container with its new port mapping while retaining its named data volume.

### Rebuilds while the portal is running

The Make startup helper now validates the selected Spring Boot JAR and runs a unique snapshot under `%LOCALAPPDATA%/ExampleBank/runtime` (override with `BANK_RUNTIME_DIR`). Rebuilding or cleaning Maven's `target` directory cannot change the active JVM's JAR. The helper removes only its own snapshot after the Java process exits. A process started directly from a JAR in `target` must be stopped before rebuilding that file.

The earlier live rebuild replaced the original default JAR with a thin archive before repackaging failed. If that archive is still selected, the helper rejects it with a clear error. Stop the old portal, then either run `make build` to restore the standard executable JAR or select `target/bank-onboarding-0.1.0-SNAPSHOT-diagnostic.jar` through `BANK_JAR`. Do not change Logback dependencies to address class-loading errors from an overwritten running JAR.

## Cloudflare hosting

The canonical bank origin is now **https://hr.bank.darkedges.com**. The app still listens over HTTP on host port 8094; Cloudflare terminates public HTTPS. It processes forwarded headers, uses Secure session cookies by default, and uses the explicit callback `https://hr.bank.darkedges.com/login/oauth2/code/hr`.

1. From `terraform/pingfederate`, run `terraform plan -out=bank-hr.tfplan`, review the callback change, then `terraform apply bank-hr.tfplan`. The local `terraform.tfvars` and the default/example configuration have been updated. Reuse the existing secrets. Apply before restarting: the Make helper reads the canonical URL from applied Terraform outputs.
2. In your existing Cloudflare Tunnel, add the published hostname `hr.bank.darkedges.com` and route all paths to the bank service. Use `http://localhost:8094` if cloudflared runs on this Windows host. For a Docker-hosted connector, use `http://host.docker.internal:8094`. For the existing Kubernetes connector, use the Windows host's reachable LAN address, for example `http://10.0.0.35:8094` on the inspected machine, and verify reachability from that connector. Do not use the connector container/pod's own localhost for a service running on Windows.
3. Allow Cloudflare to create the tunnel DNS route for this hostname. This project does not contain Cloudflare account credentials and has not applied tunnel/DNS changes. See [Cloudflare published application routing](https://developers.cloudflare.com/tunnel/concepts/routing/).
4. Stop the old bank process. Select the latest normal JAR and start it: `$env:BANK_JAR = "$PWD\target\bank-onboarding-0.1.0-SNAPSHOT.jar"`, then `make start`.
5. Open `https://hr.bank.darkedges.com/hr` and sign in again. Invitations, wallet request URLs, issuer metadata, and new staff credentials use the public origin. USB forwarding is unnecessary for this public-host flow.

The tunnel must preserve the public Host and HTTPS forwarding information. Keep direct access to the HTTP origin private so forwarding headers come from your trusted proxy. Native wallet calls to `/vp/**`, `/.well-known/**`, `/token`, `/nonce`, `/credential`, `/jwks`, and `/vct/**` must reach the bank service without an interactive Cloudflare Access or browser challenge screen. Set `BANK_TOKEN_DEBUG_ENABLED=false` when token inspection is no longer needed.

Any credentials previously issued under a localhost issuer retain that original issuer and do not become public-host credentials merely by changing configuration. Test with a fresh onboarding run when moving the demo to its new canonical origin.

For intentional local-only development, set Terraform's `bank_base_url` to `http://localhost:8094` and apply that callback configuration, then start with `BANK_COOKIE_SECURE=false`. Public hosting uses the default `true` value. Do not alternate origins within one onboarding session.

## Configuration

Use Java 21+ and Maven. Build and install the sibling `oid4vp` reactor before building this module. Create PostgreSQL with `docker compose up -d` in this directory after setting `BANK_DATABASE_PASSWORD`. The initial schema is idempotent and applied at startup; keep database backups private.

Required environment variables:

- `BANK_DATABASE_PASSWORD` (and optionally `BANK_DATABASE_URL`, `BANK_DATABASE_USER`).
- `BANK_OIDC_CLIENT_ID`, `BANK_OIDC_CLIENT_SECRET`.
- `BANK_PRIVATE_JWK_FILE`: path to a persistent private P-256 JWK. Generate one using `java tools/GenerateBankKey.java <path outside the repository>`. Restrict file access to the service account.
- `PASSPORT_PUBLIC_JWK_FILE`: path to a trusted passport issuer public P-256 JWK obtained independently from its operator. Do not trust a key delivered inside an applicant credential. The issuer's `/jwks` publishes its public keys; select the intended signing key and save that single JWK object.

Defaults: bank name `Risk E Bank`, bank URL `https://hr.bank.darkedges.com`, passport issuer `https://issuer.zkp.au`. Set `BANK_NAME`, `BANK_BASE_URL`, and `PASSPORT_ISSUER` as needed. Use one canonical bank origin consistently. The bank issuer must not be exposed under additional hostnames.

## HR provider setup

A runnable [Terraform project](terraform/pingfederate/README.md) creates the confidential client and dedicated roles policy using your existing PingFederate authentication and token configuration.


Retrieve `https://id.ping.darkedges.com/.well-known/openid-configuration` and set `BANK_OIDC_ISSUER` to its exact advertised issuer (default `https://id.ping.darkedges.com`). Discovery was verified during implementation: issuer `https://id.ping.darkedges.com`, authorization endpoint `/as/authorization.oauth2`, token endpoint `/as/token.oauth2`, and JWKS `/pf/JWKS`. The provider advertises `groups` but does not currently advertise `roles`; the custom `roles` claim still needs operator configuration. Its edge rejects the default Python urllib user agent, so administrative discovery requests should identify the application.

Register a confidential authorization-code client. Allow `<BANK_BASE_URL>/login/oauth2/code/hr` as the exact callback. Allow `openid profile`; emit a JSON array `roles` in the ID token or userinfo with `bank-hr` only for authorized HR users. Missing or other roles do not grant HR access. Secrets belong in environment configuration, never source control.

## Run and demonstrate

1. In `oid4vp`: `mvn install -DskipTests`. In `oid4vci`: `mvn -pl bank-onboarding -am package`.
2. Run `java -jar bank-onboarding/target/bank-onboarding-0.1.0-SNAPSHOT.jar` with the configuration above.
3. Open `/hr`, sign in as an HR administrator, enter the expected hire details, and copy the invitation link.
4. Open the invitation in a browser and keep that browser session. Obtain a PassportCredential in the Android wallet using its proofing option, with the real proofing app installed and its backend callback configured.
5. Choose Present passport credential. Open the wallet link or paste the request URL into the wallet. Approve disclosure, then return to the browser and choose Continue.
6. HR compares the expected and passport identity against recruitment records. Every approval is manual; differences require an explanation. Approve the hire.
7. Refresh onboarding, collect the offer, and open the wallet link (or paste its JSON into the wallet). The wallet reuses the proven passport holder key. A different wallet cannot collect the staff credential. Expired offers can be regenerated. Delivery retries return the original credential.
8. On the bank home page choose staff sign-in, paste the new presentation request URL into the wallet, present the staff credential, and return to the browser. HR deactivation blocks subsequent portal access, including existing sessions.

A physical phone cannot access the host through its own localhost. For a USB demonstration use `adb reverse tcp:8094 tcp:8094`, or configure a phone-reachable LAN origin consistently for both browser and wallet. If Android denies cleartext HTTP, use the project's development network configuration or a trusted HTTPS endpoint. Public hosting requires HTTPS and secure session cookies.

### Signed-in user receives HTTP 403 on HR pages

Open `/account/access` to see whether the identity provider returned a `roles` array and which role values this account received. Access to this page requires authentication. By default it displays only role information. The optional token debug mode below displays tokens only for that same authenticated session. HR authorization still requires the exact array value `bank-hr`. A group value containing a full LDAP DN does not match that value automatically. The Terraform policy maps the configured authenticated token attribute to `roles`; the user's upstream membership/mapping must supply the intended value.

An HR access denial now renders this page with HTTP 403 instead of the generic Whitelabel page. Use its Sign out button, then sign in again after updating group membership or the authenticated claim mapping. Do not bypass authorization or grant a constant HR role to all users to resolve this error.

### ID and access token debug view

To inspect why the provider is not releasing roles, enable the debug view before starting the portal:

```powershell
$env:BANK_TOKEN_DEBUG_ENABLED = 'true'
$env:BANK_JAR = "$PWD\target\bank-onboarding-0.1.0-SNAPSHOT-token-debug.jar"
make start
```

Stop the previous portal first. Open `/account/access` and sign in again after restarting. The token-debug build is packaged separately from the earlier diagnostic build. A later normal `make build` also includes this feature.

When enabled, the page shows the ID token's login-validated claims, UserInfo claims if available, the access token's scopes/expiry, decoded JWT access-token header/claims when possible, and expandable raw ID/access tokens with copy buttons. Opaque or encrypted access tokens are shown as raw strings with an explanation instead of a parsing error. The access token is retrieved from this user's authorized-client repository entry. Refresh tokens and client secrets are not exposed.

The page remains authenticated and uses the existing no-store and no-referrer headers. No token values are written to application logs or sent to external debugging services. Decoded access-token claims are for inspection only; they do not grant HR access. Set `BANK_TOKEN_DEBUG_ENABLED=false` and restart to disable the debug view after troubleshooting. Raw access tokens are usable credentials; keep them local.

### Use the existing PingFederate groups claim for HR access

This provider was observed issuing a verified ID token with `groups: "bank-hr"` and no `roles` claim. To use that authenticated membership, set `BANK_HR_CLAIM=groups` before startup. In this mode an exact scalar `bank-hr` or an array containing `bank-hr` grants HR access. Matching remains case-sensitive and does not split comma-delimited values or interpret LDAP DNs.

The default `BANK_HR_CLAIM=roles` retains the original roles-array requirement. There is no automatic fallback between claims. The selected claim is read from the login-validated OIDC user; decoded access-token debug claims never grant authority. `/account/access` displays the configured claim and normalizes a scalar group for display. Restart and sign in again after changing this setting.

### HR decision feedback

The HR page shows actions that are valid for each hire's current state. Approval is available after identity presentation reaches REVIEW; deactivation is available for ACTIVE staff. APPROVED hires are directed to collect their staff credential from the applicant's onboarding session. Repeating the same completed decision returns to HR without overwriting the original reviewer/reason or adding another audit event. Conflicting or premature decisions and unexplained identity mismatches return to the HR page with a validation message.

### Revoke an approved hire

On `/hr`, an APPROVED hire now has a **Revoke approval** button and a required reason field. Revocation moves the record to REVOKED, retains the original approval/identity data, and stores the revocation actor, reason and timestamp with a separate audit event. It blocks invitation reuse, new offer collection, outstanding-offer credential issuance, and staff access if issuance completed concurrently. Repeating revocation does not overwrite the first revocation record.

A revoked record cannot be approved again directly. Use Start reactivation to create a linked fresh attempt requiring another passport presentation and HR approval. This withdraws the bank's approval and access; it does not revoke the independent passport credential or remove an issued credential from a wallet. Existing ACTIVE staff can still be disabled through Deactivate staff.

The idempotent startup schema adds nullable revocation metadata columns and an audit-reason column. Existing records are retained. Restart into the updated JAR to apply these additions and display the new control.

### Start reactivation after revocation

A REVOKED hire now has a **Start reactivation** button. It creates a new invitation valid for seven days and copies the expected hire details into a new linked INVITED attempt. Share the new link with the applicant. The new attempt requires a fresh holder-bound passport credential presentation and a new HR decision before a new staff credential can be collected. A still-valid passport credential may be reused as evidence; this action does not force another mobile NFC/liveness run.

The previous attempt remains REVOKED, retaining its verified identity, reviewer, decision, revocation metadata, and audit history. Old invitations, outstanding offers, portal sessions, and staff credentials continue to refer to that revoked record; approving the new attempt does not reactivate them. The new attempt receives a new staff identifier when issued. HR cards link previous and subsequent attempts.

Repeated submissions return to the existing followup instead of creating duplicate requests or rotating its invitation. A revoked attempt can have only one followup. If that followup is later revoked, request verification again from that most recent revoked card. The startup schema adds a nullable previous-attempt reference and a unique followup index without changing existing hire statuses.

## State and trust

Invitation tokens are hashed, expire after seven days, and are replaced on reissue. Presentation transactions expire after ten minutes and are bound to the initiating browser. PostgreSQL persists hire state, verified name/birth date, holder public key, decisions, timestamps, audit events, and the issued staff credential. It stores no passport images, passport number, or face templates. Restrict database access accordingly.

Offers and access-token claim state remain short-lived in-memory library stores. After restart, request a fresh offer; HR approval survives. Staff credentials last 30 days. Renewal and wallet-key recovery are not implemented; do not delete the original holder key.

Proofing is still a PoC. This integration does not establish an independently measured biometric false-match rate or add presentation-attack detection. The bank trusts only its pinned passport issuer key and its own staff signing key. Configure key rotation deliberately; there is no automatic trust of embedded x5c certificates.

## Journey API for Authr

The applicant and staff sign-in journeys can also run in Authr (a flow engine) instead of this portal's pages. Authr calls
`/api/journey/v1` as a machine client; HR stays in this portal. The bank stays authoritative: every decision is made here, as the portal
makes it, and Authr is never trusted to say that something was approved or presented.

| Call | Does |
|---|---|
| `POST /invitations/redeem` `{inviteToken}` | Checks the invitation as `/invite/{token}` does and returns a 30-minute opaque `applicantRef` and the `stage`. 404 `invalid_invitation`, 410 `invitation_expired`, 409 `invitation_closed`. |
| `GET /applicants/{ref}` | `stage`: `present`, `in_review`, `collect`, `active` or `closed` (a newer attempt also closes the old one). |
| `POST /applicants/{ref}/presentations` | Starts a Passport presentation, only while INVITED (409 `wrong_stage`). Returns `presentationId`, `walletUri`, `expiresAt` and a `completionSecret`. |
| `POST /staff-sign-in/presentations` | Starts a staff-credential presentation (rate-limited per client: 429 `rate_limited`). |
| `GET /presentations/{id}` + `X-Completion-Secret` | `pending`, `complete` or `expired`, as `/vp/status`. Another journey's presentation, or a portal one, is 404. |
| `POST /presentations/{id}/consume` + `X-Completion-Secret` | Takes the result once (409 `already_consumed`). Staff: re-checks that the staff member is still active (409 `staff_inactive`) and returns `staffSubject`. |
| `POST /applicants/{ref}/credential-offers` | The staff credential offer, only when APPROVED or ACTIVE and not superseded (409 `wrong_stage`). |

The wallet side does not change: it still fetches `/vp/request/{id}` and posts to `/vp/response/{id}`, where every check (issuer, type,
signature, holder binding, nonce, audience, expiry, replay, fresh proofing, evidence) is made.

Callers need an AuthStack client-credentials token from `BANK_JOURNEY_ISSUER`, with audience `BANK_JOURNEY_AUDIENCE` (default
`bank-journey`), scope `BANK_JOURNEY_SCOPE` (default `bank.journey`), from a client in `BANK_JOURNEY_CLIENTS`. With no issuer the API is
off. `BANK_JOURNEY_JWK_SET_URI` overrides key discovery.

`BANK_APPLICANT_ENTRY=authr` with `BANK_APPLICANT_ENTRY_URL` makes new invitation links open the Authr journey
(`<url>#invite=<token>`: in the fragment, so the token never reaches a server log). The default, `portal`, keeps `/invite/{token}`; links
already sent keep working either way. In `authr` mode, this portal's own applicant pages are retired:
- `/onboarding`, `/onboarding/present` and `/onboarding/offer` answer 404;
- an old `/invite/{token}` link forwards to the Authr journey, with the token moved into the URL fragment.

Likewise, `/staff/login` answers 404 while staff sign in through AuthStack. Switching either setting back restores the pages.

The startup schema adds `bank_applicant_ref`, and `channel` and `consumed_at` columns. Presentations and applicant references now take
their expiry from the database's clock, which is also what checks it. The portal's own `Present` action now also refuses a hire that is
no longer awaiting identity, and a presentation that fails verification answers 400 rather than a server error.

## Staff sign-in through AuthStack

With `SPRING_PROFILES_ACTIVE=authstack-staff`, the home page's **Sign in with staff wallet** goes through AuthStack. It replaces the bank
page's own wallet sign-in, which comes back when the profile is off. The isolated showcase therefore keeps its recorded flow. The steps
are:

1. The browser goes to Authr's hosted sign-on page, which runs the `bank-staff-signin` flow.
2. The wallet presents the staff credential to this bank's `/vp/response`. Every check is unchanged.
3. The flow takes the result through the Journey API, which checks again that the staff member is still active.
4. AuthStack issues an authorization code for the identity `staff-<staff id>@<BANK_STAFF_EMAIL_DOMAIN>`.
5. The bank exchanges the code with its client secret. It reads the staff id back from the ID token's email and checks the staff member
   is active and not superseded. Only then does it give the browser the same staff session a portal sign-in gives.

`/staff` checks the staff member again on every request, so revoking approval still ends access at once. **Log out** ends the staff
session completely: the sign-in leaves no session at AuthStack or Authr (`bank-staff-signin` has no single sign-on), so the next sign-in
always asks for the wallet again. The AuthStack sign-in itself is not
kept, and it never grants HR access: the HR role comes only from the HR provider.

The values come from the authstack repo's `terraform/risk-e-bank` outputs: `bank_staff_env` and `staffPortalClientSecret`. To switch it off,
remove `SPRING_PROFILES_ACTIVE`.

## Staff in the AuthStack directory

With `BANK_AUTHSTACK_*` set, every person HR hires gets a user in the bank's AuthStack environment, and the bank keeps it current.

**One user per person.** A reactivation creates a new attempt, but the person keeps the same AuthStack user:
- email `staff-<person id>@BANK_STAFF_EMAIL_DOMAIN`, where the person id is the first attempt's id;
- `externalId` = the person id;
- population "Staff";
- the recruitment names, replaced by the Passport-verified names once approved.

The user is **enabled only while the person is active staff**, and AuthStack refuses sign-in to a disabled user.

**The bank's view of the person** is on the user, as the external identity `risk-e-bank` (`PUT /v1/environments/:env/users/:id/externalIdentities/risk-e-bank`):
- lifecycle state and reason;
- identity verification, including whether a fresh Passport check is required;
- every attempt;
- the staff credentials issued, each ACTIVE, SUPERSEDED, REVOKED, INACTIVE or EXPIRED;
- last sign-in;
- the operations the bank offers now.

No credential, birth date or personal email is sent.

**Every change is queued in `bank_directory_outbox`** in the same transaction: create, Passport presented, decisions, reactivation, issuance and staff sign-in. A scheduled job then sends the person's whole current state, retrying with backoff. HR's card shows `AuthStack: synced`, `pending` or `failed`.

**The AuthStack console can revoke, deactivate and start a reactivation** on the person's page. AuthStack relays the administrator's choice to `POST /api/directory/v1/people/{personId}/actions`, with that administrator's own console token. The bank checks the token with AuthStack (`BANK_AUTHSTACK_CONSOLE_ME_URL`): an ADMIN or ORG_ADMIN whose organisation owns the bank's environment. It then applies the action with the same rules as HR's page, auditing it with channel `authstack`. Approving and rejecting stay with HR.

**Staff sign-in names the person.** The bank maps that to the person's current attempt and requires it to be active. Identities created per attempt, before this change, still sign in.

## Validation limits

Run module tests through Maven, wallet TypeScript checks, backend pytest, and the Android walkthrough. Provider registration, live PostgreSQL, and real-device acceptance require operator configuration. This implementation has not yet been validated against those live systems.


### Email verification invitations with Mailgun

New hires, replacement invitations, and verification requests created after revocation
are emailed to the contact email stored on the hire when mail is enabled. HR never
supplies a different recipient on the send action. Existing invited hires have a
**Replace and email invitation** action. This creates a new seven-day link and
invalidates the old link. Repeated re-verification submissions keep the existing
followup; use its replacement action to send again.

Configure the same PowerShell session that runs `make start`:

```powershell
$env:BANK_MAIL_ENABLED = 'true'
$env:BANK_SMTP_HOST = 'smtp.mailgun.org' # use your Mailgun region's SMTP host
$env:BANK_SMTP_PORT = '587'
$env:BANK_SMTP_USERNAME = 'hr@sandbox0fed9dd3c01d4a00b5315d38226da368.mailgun.org'
$env:BANK_MAIL_FROM = 'hr@sandbox0fed9dd3c01d4a00b5315d38226da368.mailgun.org'
$smtpPassword = Read-Host 'Mailgun SMTP password' -AsSecureString #
$env:BANK_SMTP_PASSWORD = [Net.NetworkCredential]::new('', $smtpPassword).Password
make build
make start
```

Use your domain's SMTP credentials, available in Mailgun under Sending > Domain
Settings > SMTP Credentials, and a sender on your verified sending domain.
[Mailgun SMTP documentation](https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/send-smtp)
recommends port 587. The bank requires STARTTLS and certificate hostname validation.
The Mailgun API key is not the SMTP password. Credentials are read from environment
variables and are not stored in Terraform, source files, or email templates.

The invitation is committed before sending. SMTP failures leave the invitation
available and show a failure on the invitation page; use the replacement action
after correcting SMTP settings. An accepted message means the SMTP provider
accepted it, not that it reached the inbox; check Mailgun delivery events for bounces.
There is no background retry queue. If the process stops after saving an invitation,
use the same replacement action. Email contains the personal HTTPS onboarding link
and instructions, without passport details or wallet retrieval secrets.

Email is disabled by default. Existing manual sharing remains available until SMTP
is configured. Restart the bank after changing mail settings. No mobile app update
is required for email delivery.


For Mailgun sandbox domains, add the hire's contact email under authorized
recipients and ask them to accept Mailgun's verification email before sending.
Use the exact login listed in SMTP Credentials; choosing a From address does not
create an SMTP user. Authentication, DNS, connection, TLS, and sender/recipient
rejections appear as safe diagnostic categories on the invitation page and in
bank logs. Raw SMTP responses and exception messages are not displayed or logged.


### Live HR request status

Keep `/hr` open to watch requests. It polls every five seconds while visible and
refreshes immediately when returning to the tab. Hire cards, status, verified
details, and available actions update without reloading the create form or losing
typed decision notes. A visible live announcement and updated page title notify
watchers when identity arrives for review, approval is granted, or staff becomes
active. Existing approvals do not produce notifications on initial page load.
Updates require an authenticated HR session. Network errors retry automatically;
if the session expires, reload and sign in. No email or browser notification
permission is needed. Restart the bank with the updated JAR to enable this.


### Scan wallet requests and collect staff credentials

Passport presentation, staff sign-in, and staff credential offer pages include locally
generated QR images. Open Scan in the Android wallet to scan from a desktop. The
same-device wallet links and paste fallbacks remain available. Keep the initiating
browser open and use Continue after presentation there when the wallet succeeds.
Requests and offers expire after ten minutes; start again if expired.

A Passport credential cannot sign in to staff services. Present it through your
onboarding invitation, wait for HR approval, then collect the approved staff offer
in the same wallet. Accept and obtain the staff credential before starting a new
staff sign-in request. Credential type URLs remain exact and case-sensitive.


Presentation pages poll every two seconds while visible and automatically use the
existing browser-bound continuation after the wallet succeeds. This covers staff
sign-in and Passport onboarding. Status checks require the initiating session and
do not sign anyone in themselves. Expiry stops polling; transient failures retry.
The manual continuation link remains available.


### Log out

Log out appears only when the browser has authenticated HR access, staff access, or an applicant onboarding session. An anonymous root page (including one with only an empty or CSRF session) hides it. Use Log out to end the current bank browser session.
This clears HR authentication, staff access, applicant state and outstanding
presentation session proofs, deletes the session cookie, and returns to the home
page. The POST form uses the existing CSRF protection. Wallet credentials remain
in the mobile wallet. This is local bank logout; PingFederate SSO is not terminated.


### Local .env configuration

Every Make target automatically reads `bank-onboarding/.env`. Run `make env` to
create it from `.env.example` if absent; existing files are never overwritten.
The template lists bank branding, SMTP, database, OIDC, keys, Java, build, and
network settings. Edit `.env` once, then run `make start` without setting shell
variables each time. No bank JAR rebuild is needed for this helper change.

Existing nonempty shell variables override `.env`; clear an old override with
`Remove-Item Env:BANK_NAME` (for example) if you want the file value. Blank entries
leave defaults, Terraform discovery and secure prompts intact. Explicit OIDC
settings override Terraform discovery; if client ID, issuer and base URL are all
provided, Terraform outputs are not required. The client secret can still be
read from state/configuration unless supplied explicitly.

Values are literal `KEY=value` or quoted `KEY='value'` / `KEY="value"`. Put comments
on separate lines; there is no interpolation, escaping or shell execution. Quote
passwords that have leading/trailing spaces. Never paste `$env:` PowerShell
assignments into this file. Parse errors report line numbers without printing values.

The local `.env` is ignored by Git; `.env.example` contains no secrets and is tracked.
Passwords stored in `.env` are plaintext on disk: leave them blank to be prompted
securely instead. With email enabled, startup prompts for the SMTP password if
missing. Use the rotated SMTP password after the earlier exposed credential.
Restart the bank after editing `.env`; settings apply only inside the Make task.


### Force a fresh Passport check after revocation

On a revoked hire without a followup, tick Require a fresh Passport check in
Identity Proofing before Start reactivation. The new invitation records
a cutoff; the wallet launches Identity Proofing if it has no qualifying credential.
The bank requires an issuer-signed proofed_at timestamp at or after that cutoff,
independently of wallet behaviour. Missing, older, invalid or future timestamps
are rejected. Existing credentials remain usable for ordinary requests.

Deploy the rebuilt Passport issuer (which stamps successful proofing results),
restart the bank (which adds the nullable cutoff column), and update the wallet.
The requirement survives invitation replacement and is audited. Duplicate
re-verification submissions return the existing attempt without changing its
requirement. A qualifying Passport can be reused for that same attempt if the
presentation request expires; another revocation can create a new cutoff.


### Current attempts and reactivation

HR lists the latest attempt of each linked onboarding chain. Earlier attempts
are retained under Previous verification attempts with navigation to their
followups. Polling updates both areas without duplicating moved cards. Separate
records created independently are not merged just because names or emails match;
record IDs distinguish them. No stored verification or audit history is deleted.

REVOKED, INACTIVE, CANCELLED and REJECTED current attempts offer Request
verification again, including the fresh Passport checkbox. This starts
reactivation through a new invitation, presentation and HR approval. It does not
restore access on the old record or reactivate its old credential. If a followup
already exists, use that current attempt: replace its invitation while INVITED,
approve it while REVIEW, or collect its credential while APPROVED.


### Superseded staff credentials

Staff sign-in must present the issuer JWT of the canonical issued credential saved
on the active hire. A trusted signature alone is insufficient. Access and issuance
also reject attempts with a linked followup, so an old copy cannot restore access
after reactivation has superseded its record. No data migration is required;
restart the rebuilt bank to apply these checks.

### Isolated narrated demonstration

See [demo/README.md](demo/README.md) for the repeatable narrated Risk E Bank
showcase and [presenter runbook](demo/RUNBOOK.md). It runs the actual bank, wallet
and proofing interfaces with separate services, fictional identities and explicitly
simulated Passport hardware. It covers invitation through sign-in, plus revocation
and controlled reactivation. Existing bank and wallet data are not used.
