# OpenID Conformance Suite automation

Automates running the OpenID Foundation's conformance suite against
`https://issuer.zkp.au` (this repo's Cloudflare-tunneled `oid4vci-demo-issuer`), replacing manually
clicking through [demo.certification.openid.net](https://demo.certification.openid.net)'s UI for every
re-run.

## What this tests

Test plan `oid4vci-1_0-issuer-haip-test-plan[credential_format=sd_jwt_vc]` — "OpenID for Verifiable
Credential Issuance 1.0 Final/HAIP: Test an issuer" — covers the full HAIP profile: metadata, DPoP-bound
token issuance, `attest_jwt_client_auth`, proof-of-possession, batch issuance, and the SD-JWT VC `x5c`/`vct`
checks. This superseded an earlier, narrower setup that only ran `VCIIssuerMetadataTest`/
`VCIIssuerMetadataSignedTest`.

`credential_format` is a required variant with no default (`AbstractVCIIssuerTestModule`'s
`@VariantParameters` declares it; the plan-creation API rejects the request outright without it —
confirmed live, `run.sh` failed with `TestModule 'oid4vci-1_0-issuer-happy-flow' requires a value for
variant 'credential_format'` before this was added). Its only two values
(`net.openid.conformance.variant.VCI1FinalCredentialFormat`) are `sd_jwt_vc` (→ `dc+sd-jwt`) and `mdoc`
(→ `mso_mdoc`); `sd_jwt_vc` matches `UniversityDegreeCredential` (`vci.credential_configuration_id` in the
config), this issuer's `dc+sd-jwt` credential.

## Prerequisites

- The issuer must actually be reachable at `https://issuer.zkp.au`. That domain only resolves while the
  Cloudflare tunnel overlay is running (see the root README's "Hosting behind Cloudflare"):
  ```bash
  CLOUDFLARE_TUNNEL_TOKEN="<token from the dashboard>" docker compose \
    -f docker-compose.yml -f docker-compose.cloudflare.yml -f docker-compose.tunnel.yml up -d --build
  ```
  `run.sh` does a quick health check first and warns (doesn't silently fix anything) if the issuer isn't
  responding.
- A `CONFORMANCE_TOKEN` — an API token from your `demo.certification.openid.net` account (Account -> API
  tokens).
- Python 3 available on `PATH` (`run.sh` creates its own virtualenv under `conformance/scripts/.venv` on
  first run, so no dependency on the ambient Python environment beyond that).

## Running it

```bash
CONFORMANCE_TOKEN=<your token> ./conformance/run.sh
```

Any extra arguments are passed straight through to `run-test-plan.py`, e.g.:

```bash
CONFORMANCE_TOKEN=<your token> ./conformance/run.sh --verbose
CONFORMANCE_TOKEN=<your token> ./conformance/run.sh --list                    # show plan/variant list, don't run
CONFORMANCE_TOKEN=<your token> ./conformance/run.sh --expected-skips-file conformance/expected-skips.json
```

By default this targets the hosted `https://demo.certification.openid.net`. Override `CONFORMANCE_SERVER`
to point at a different instance (see "Self-hosting" below).

## Config: real vs. example

- `oid4vci-issuer-haip-test-config.json` — the real config, **gitignored, never committed**. Contains live
  private key material: the test wallet's signing key (`client.jwks`) and, critically, the Wallet
  Provider attestation key's private half (`client_attestation.attester_jwks[].d`) — this project's own
  `oid4vci-demo-issuer/src/main/resources/application.yml` already documents that this exact key's
  private half belongs "in the conformance suite's own test configuration ... never in this repo," and
  this file is that configuration.
- `oid4vci-issuer-haip-test-config.example.json` — tracked in git, same shape, placeholder secrets — so the
  setup is discoverable without needing the real key material. Copy it to the real filename and fill in
  actual values to get started:
  ```bash
  cp conformance/oid4vci-issuer-haip-test-config.example.json conformance/oid4vci-issuer-haip-test-config.json
  ```

Two fields worth knowing about if the issuer's key material changes (e.g. the signing keystore is ever
regenerated, as happened once already this project's history to fix a HAIP `x5c` chain check):
- `credential.trust_anchor_pem` must be the **root CA cert** (`demo-issuer-signing-key.p12`'s issuing
  "oid4vci Demo CA", not the leaf) — the credential's own `x5c` only ever carries the non-self-signed leaf
  (see `DemoIssuerKeyConfig.java`), so the suite needs this root supplied separately to validate the chain
  against.
- `credential.status_list_trust_anchor_pem` doesn't currently correspond to anything this issuer
  implements — this codebase has no OAuth Status List support yet, so any status-list-specific checks
  should just not apply. Left as-is rather than invented.

## Vendored scripts

`scripts/run-test-plan.py`, `scripts/conformance.py`, `scripts/test_plan_parser.py`, and
`scripts/certs-keys/` (unconditionally required by `run-test-plan.py` even though its contents are for
unrelated OpenID4VP RP test scenarios — the script fails outright if that directory doesn't exist) are
vendored, not submoduled, from
[`gitlab.com/openid/conformance-suite`](https://gitlab.com/openid/conformance-suite) pinned at commit
[`daf33d61b982d5d33d134b07e9a36f76176b3eff`](https://gitlab.com/openid/conformance-suite/-/commit/daf33d61b982d5d33d134b07e9a36f76176b3eff)
(2026-07-29). Re-vendor deliberately (re-run the same `curl .../-/raw/<new-commit>/scripts/...` fetches)
rather than letting these drift silently — update the pinned commit here when you do.

### Patches on top of the vendored scripts

`run-test-plan.py`'s own `WAITING`-state handling only automates a few hardcoded scenarios (Node.js
sample clients, FAPI/Brazil/KSA `subprocess` calls) — nothing in the `net.openid.conformance.vci10issuer`
package matches any of them, so an OID4VCI issuer test module hitting `WAITING` (which every one of them
does, once per authorization round — this plan fixes `vci_grant_type=authorization_code`, not
`pre-authorized_code`) would otherwise just sit there forever with nothing driving it forward.

Confirmed live that `oid4vci-demo-issuer`'s `/authorize` endpoint has no real login/consent screen
(`DemoAuthorizationClaimsResolver` auto-approves — see the root README on why there's no login anywhere in
this demo) and completes in a single 302 redirect straight to the suite's own callback URL given a plain,
unauthenticated `GET` — so "visiting a browser" for this specific issuer is really just following one
redirect chain. `run-test-plan.py` has a local patch (an `elif re.match(r'oid4vci-1_0-issuer-.*', module)`
branch right before the final `wait_for_state(module_id, ["FINISHED"])`) that does exactly that: scans the
module's log for the latest not-yet-followed `redirect_to` entry and issues a plain `httpx` GET
(`follow_redirects=True`) at it, repeating (bounded to 10 iterations) for as long as the module keeps
re-entering `WAITING` — `oid4vci-1_0-issuer-happy-flow-additional-requests` does more than one
authorization round in a single module run.

**Race condition (confirmed live):** a module's status can flip to `WAITING` slightly before the
"Redirecting to authorization endpoint" entry is actually appended to its log — the status-change
notification and the log write aren't atomic. An immediate `get_test_log()` can see neither a redirect nor
an `implicit_submit` entry yet and wrongly conclude there's nothing to follow, permanently stalling that
module (this is exactly what "it's still getting stuck" turned out to be). The patch retries up to 5 times,
1 second apart, before actually giving up on a given `WAITING` cycle.

Every check the patch makes prints an `[oid4vci-patch] ...` line — which redirect/implicit URL it's
following, or (on an empty check) how many log entries exist and what the last one was, so a stuck run is
diagnosable from `run.sh`'s own output rather than needing a separate `inspect-module.py` call.

This patch is **not upstream** and will be silently lost on a re-vendor — re-apply it (or something
equivalent) after re-fetching a newer pinned commit. It's specific to this issuer's no-login design; a
real Wallet/issuer pairing that needs actual user consent would need a real browser (or a proper headless
browser automation) instead.

## Self-hosting instead of the hosted demo site

Not set up yet, and not required for the automation above — `run-test-plan.py` already supports either
via one env var:

```bash
export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443   # a self-hosted instance
# vs. the default: https://demo.certification.openid.net
```

Self-hosting the suite's own Java/MongoDB/Nginx server is a separate, heavier undertaking (clone
`gitlab.com/openid/conformance-suite`, build it, `docker compose up`) that wasn't pursued yet — revisit
this only if the hosted demo site's availability or rate limits become a real problem.
