# OpenID4VCI on Spring Security

A Java implementation of OpenID for Verifiable Credential Issuance (OID4VCI) 1.0, sharing the Spring
configuration conventions and credential-format handling of the sibling
[oid4vp](../oid4vp) project (OpenID4VP 1.1 — presentation).

## Modules

| Module | Purpose |
|---|---|
| `oid4vci-core` | Format-agnostic protocol model: Credential Offer, Credential Issuer Metadata, Credential Configuration, Token/Nonce request-response, Credential Request/Response, Proof-of-Possession JWT constants |
| `oid4vci-test-fixtures` | Hand-transcribed OID4VCI spec examples (no bulk `examples/` directory exists upstream to vendor wholesale) |
| `oid4vci-issuer-core` | Non-Spring Issuer orchestration: pre-authorized-code bookkeeping, nonce issuance, access-token minting, proof-of-possession verification, per-format credential building |
| `oid4vci-wallet-core` | Non-Spring Wallet orchestration: credential-offer parsing, token exchange, proof building, dispatches issued credentials into `oid4vp-core`'s `HeldCredential` |
| `oid4vci-issuer-web` | Plain Spring MVC controllers over issuer-core — no custom `AuthenticationProvider`; the Credential Endpoint's bearer-token check is a standard `oauth2ResourceServer()` concern, not a novel authentication act the way validating a `vp_token` is in oid4vp |
| `oid4vci-spring-boot-autoconfigure` | `oid4vci.issuer.*` properties and default beans |
| `oid4vci-demo-issuer` | Runnable demo Issuer app — live-tested end to end for both formats, see "Running the demo issuer" below |
| `oid4vci-demo-wallet` | Runnable demo Wallet app — live-tested obtaining both formats from `oid4vci-demo-issuer` over real HTTP, see "Running the demo wallet" below. Also depends on `oid4vp-wallet-core`; its `/present` endpoint presents an obtained credential to a separately-running `oid4vp-demo-verifier` — live-tested end to end for both formats, see "Cross-repo interop" below |

## Prerequisites

- **Java 21** and **Maven 3.9+** (see [oid4vp's README](https://github.com/darkedges/spring-boot-oid4vp/blob/main/README.md#prerequisites) for a local,
  no-root install if you don't have them).
- **The sibling `oid4vp` reactor must be built and installed into your local `~/.m2` first** — this
  project depends on `oid4vp-core`, `oid4vp-format-sdjwt-vc`, `oid4vp-format-mdoc`, and (from the demo
  Wallet onward) `oid4vp-wallet-core` as ordinary SNAPSHOT Maven dependencies, resolved only from the
  local repository (no shared Nexus/Artifactory):

  ```bash
  cd ../oid4vp && mvn -q install -DskipTests
  ```

  Re-run this whenever `oid4vp` changes and you want oid4vci to pick it up.

## Building

```bash
mvn clean install
```

## Running the demo issuer

```bash
mvn -pl oid4vci-demo-issuer install -am -DskipTests
java -jar oid4vci-demo-issuer/target/oid4vci-demo-issuer.jar   # listens on :8092
```

Then walk the pre-authorized_code flow by hand:

```bash
# 1. Seed a demo offer (claims + pre-authorized code)
OFFER=$(curl -s http://localhost:8092/demo/offer)
CODE=$(echo "$OFFER" | jq -r '.grants."urn:ietf:params:oauth:grant-type:pre-authorized_code"."pre-authorized_code"')

# 2. Redeem it for an access token
TOKEN=$(curl -s -X POST http://localhost:8092/token \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  --data-urlencode "pre-authorized_code=$CODE" | jq -r '.access_token')

# 3. Fetch a c_nonce, build a jwt-type proof of possession bound to it (ES256, typ
#    "openid4vci-proof+jwt", the wallet's public key in the JWT header -- see ProofJwtBuilder)

# 4. POST /credential with the token + proof, credential_configuration_id
#    "UniversityDegreeCredential" (dc+sd-jwt) or "org.iso.18013.5.1.mDL" (mso_mdoc)
```

Both formats were confirmed working end to end this way against a live instance.

## Running the demo wallet

```bash
mvn -pl oid4vci-demo-wallet install -am -DskipTests
java -jar oid4vci-demo-wallet/target/oid4vci-demo-wallet.jar   # listens on :8093
```

With `oid4vci-demo-issuer` also running on `:8092`:

```bash
curl -X POST "http://localhost:8093/wallet/obtain?issuerUrl=http://localhost:8092"
curl http://localhost:8093/wallet/credentials
```

`/wallet/obtain` drives the whole flow itself — fetches the issuer's metadata and a demo offer, exchanges
the code, builds real proofs of possession, and requests both `UniversityDegreeCredential` (`dc+sd-jwt`)
and `org.iso.18013.5.1.mDL` (`mso_mdoc`) — confirmed live: both come back correctly held, with the right
claims, parsed via `oid4vp-format-sdjwt-vc`/`oid4vp-format-mdoc`'s own `HeldCredential.parse` factories.

## Cross-repo interop — Issuer→Wallet→Verifier, live-tested end to end

A credential obtained by `oid4vci-demo-wallet` from `oid4vci-demo-issuer` can be presented to a
separately-running `oid4vp-demo-verifier`, confirmed live for both formats (`dc+sd-jwt` against the
verifier's "demo" registration, `mso_mdoc` against "demomdoc", including the latter's encrypted
`direct_post.jwt` response). This closed three gaps surfaced by live testing:

1. `oid4vp-demo-verifier`'s `IssuerKeyResolver` resolves an issuer's key from the credential's own
   embedded certificate chain (SD-JWT VC's `x5c` / mdoc's `x5chain`) first, falling back to fetching a
   JWKS endpoint only for its own hardcoded `demo.wallet-base-url` — so an oid4vci-issued credential is
   only verifiable by it once the credential itself carries a certificate chain. `DemoIssuerKeyConfig`
   loads two checked-in PKCS12 keystores (`demo-issuer-signing-key.p12`, `demo-issuer-mdoc-key.p12` — same
   `keytool` technique as `demo-verifier-signing-key.p12`) instead of generating chain-less keys fresh
   every startup; both `SdJwtVcCredentialIssuanceService` (takes a `certificateChain` constructor param,
   embedding `x509CertChain` into the JWS header) and `MsoMdocCredentialIssuanceService` embed the
   resulting leaf cert. The SD-JWT VC keystore's leaf is CA-issued (not self-signed) by a throwaway
   `keytool`-generated "oid4vci Demo CA" root — the OpenID Conformance Suite's HAIP `x5c` chain check
   rejects a self-signed leaf, and separately rejects a self-signed trust anchor if it's *included* in
   `x5c`, so only the (non-self-signed) leaf goes in `x5c`, not the root. `IssuerKeyResolver` still trusts
   the embedded leaf outright either way, with no path validation.
2. `oid4vci-demo-issuer`'s `UniversityDegreeCredential` `vct` is issuer-relative (`/vct/...`), resolved
   per request against whichever base URL a client actually reached this issuer at (see
   `RequestBaseUrl`/`SdJwtVcCredentialConfiguration#resolvedVct`), with `SdJwtVcTypeMetadataController`
   serving real SD-JWT VC Type Metadata there — not the fixed `https://demo.oid4vp.example/employee_credential`
   placeholder this previously matched `oid4vp-demo-verifier`'s "demo" registration DCQL query on: the
   OpenID Conformance Suite does a real HTTP GET straight to `vct` for Type Metadata, which that
   non-routable placeholder domain could never satisfy. `oid4vp-demo-verifier`'s `application.yml` now
   lists both the placeholder (still used by `oid4vp-demo-wallet`'s own self-issued demo credential) and
   `http://localhost:8092/vct/UniversityDegreeCredential` (matching the live-tested example below) in its
   `vct_values` array — a different deployment (Docker network alias, public tunnel) needs its own entry
   there to match whatever base URL the Wallet actually used. The mdoc `doctype` and both formats' claim
   names still match regardless.
3. `WalletIssuanceOrchestrator.obtainCredentials` resolved and used a holder-binding private key during
   issuance but discarded it afterward, returning only `HeldCredential`s — leaving no way to later sign a
   presentation. It now returns `List<HolderBoundCredential>` (credential + binding `ECKey` pair);
   `MutableCredentialStore` keeps that pairing and `oid4vci-demo-wallet`'s new `/present` endpoint
   (mirroring `oid4vp-demo-wallet`'s own `WalletController.present(...)`) uses it to back a
   `HolderKeyResolver` for `WalletAuthorizationResponseBuilder`.

Try it: with `oid4vci-demo-issuer` (`:8092`), `oid4vci-demo-wallet` (`:8093`), and `oid4vp-demo-verifier`
(`:8090`) all running, and after `/wallet/obtain` as above,

```bash
curl -X POST http://localhost:8093/present -H 'Content-Type: application/json' \
  -d '{"verifierAuthorizeUrl":"http://localhost:8090/oid4vp/authorize/demo"}'      # dc+sd-jwt
curl -X POST http://localhost:8093/present -H 'Content-Type: application/json' \
  -d '{"verifierAuthorizeUrl":"http://localhost:8090/oid4vp/authorize/demomdoc"}'  # mso_mdoc
```

## Running under Docker

`docker-compose.yml` builds and runs `oid4vci-demo-issuer` and `oid4vci-demo-wallet` as containers:

```bash
mvn install -DskipTests        # from the repo root, after the sibling oid4vp prerequisite above
docker compose up --build
```

Only these two apps live here, same scope as `oid4vp`'s own `docker-compose.yml` (just its Wallet +
Verifier) — a Verifier isn't baked into this stack at all, since the Wallet's `/present` endpoint takes the
Verifier's authorize URL as a per-request parameter (see "Cross-repo interop" above), so it can target a
locally-run `oid4vp-demo-verifier`, `oid4vp`'s own `docker compose` stack, or a publicly-hosted one equally
well, with zero config here either way. To drive the same flow shown above with both apps containerized,
curl the Wallet's published port from the host but pass the **Issuer's docker-compose service name**, not
`localhost`, as `issuerUrl` — that value is resolved by the Wallet *container's* own DNS, not by your host's
`curl`:

```bash
curl -X POST "http://localhost:8093/wallet/obtain?issuerUrl=http://issuer:8092"
curl -X POST http://localhost:8093/present -H 'Content-Type: application/json' \
  -d '{"verifierAuthorizeUrl":"http://localhost:8090/oid4vp/authorize/demo"}'
```

(`verifierAuthorizeUrl` above assumes a Verifier running directly on the host, reachable at
`localhost:8090` — if it's containerized too, e.g. via `oid4vp`'s own `docker compose`, join that compose
network instead and use its service name the same way.)

`oid4vci-demo-issuer/src/main/resources/application-docker.yml` (activated by `SPRING_PROFILES_ACTIVE=docker`
in `docker-compose.yml`) overrides `oid4vci.issuer.credential-issuer` to the docker-compose service name
(`http://issuer:8092`) instead of `localhost`, since that value is embedded verbatim into the served
Credential Issuer Metadata document and must be a URL the Wallet container can actually reach.
`oid4vci-demo-wallet` needs no such file at all — every URL it calls is a per-request parameter, never
baked-in config. If you rename the `issuer` service in `docker-compose.yml`, update
`application-docker.yml` to match.

### Hosting behind Cloudflare

To expose the demo publicly — e.g. Issuer on `issuer.zkp.au`, Wallet on `vciwallet.zkp.au` (deliberately
distinct from `oid4vp`'s own `wallet.zkp.au`/`verify.irving.au` pairing — this Wallet does real issuance
and presentation, not a second self-issuing demo Wallet at the same address) — activate the **`cloudflare`**
Spring profile instead of (not in addition to) `docker`:

```bash
docker compose -f docker-compose.yml -f docker-compose.cloudflare.yml up -d --build
```

`application-cloudflare.yml` in `oid4vci-demo-issuer` sets `credential-issuer` to the public HTTPS domain
rather than the docker-compose-internal service name — same reasoning as `oid4vp`'s own
`application-cloudflare.yml` files. If you're using a different domain, edit that file (and
`docker-compose.tunnel.yml`'s comment) to match.

You still need to actually get traffic to the containers. `docker-compose.tunnel.yml` layers on a
`cloudflared` connector for this — see its header comment for the one-time dashboard setup (create a
tunnel, add the two Public Hostname routes, copy the token):

```bash
CLOUDFLARE_TUNNEL_TOKEN="<token from the dashboard>" docker compose \
  -f docker-compose.yml -f docker-compose.cloudflare.yml -f docker-compose.tunnel.yml up -d --build
```

## Known gotchas (Spring Boot 4.1 + Jackson 2/3 coexistence)

`spring-boot-starter-web` in Spring Boot 4.1 pulls in `spring-boot-starter-jackson`, which brings
**Jackson 3** (`tools.jackson.core:jackson-databind`) onto the classpath alongside whatever Jackson 2
(`com.fasterxml.jackson.core:jackson-databind`) this project (and oid4vp) already depend on directly. Both
end up bundled in the fat jar. Consequences, confirmed live against a running demo issuer, not just in
theory:

- **Returning a Jackson-2 `JsonNode`/`ObjectNode` directly from a `@RestController` method silently
  breaks**: the Jackson-3 message converter doesn't recognize the Jackson-2 type, and Spring Boot 4.1
  apparently prefers it, so it falls back to plain bean introspection — serializing `JsonNode`'s own
  `isXxx()` predicate methods as if they were getters, producing garbage like
  `{"array":false,"object":true,...}` with a 200 status and no error. oid4vp's own `AuthorizeController`
  already documented and worked around this (return a pre-serialized `String` via `.toString()`, with
  `produces = MediaType.APPLICATION_JSON_VALUE`) — every controller in `oid4vci-issuer-web` follows the
  same pattern.
- **The read side has the mirror-image failure**: `@RequestBody JsonNode` throws
  `InvalidDefinitionException: Cannot construct instance of com.fasterxml.jackson.databind.JsonNode` at
  request time, for the same reason in reverse. Fix: accept `@RequestBody String` and parse it manually
  with a local Jackson-2 `ObjectMapper` (see `CredentialController`).
- **`NimbusJwtDecoder.withJwkSetUri(...)` only trusts RS256 by default** — unrelated to the Jackson issue,
  but hit on the same live run: an ES256-signed access token was rejected with "Another algorithm
  expected" until `.jwsAlgorithm(SignatureAlgorithm.ES256)` was added explicitly (see
  `Oid4vciIssuerAutoConfiguration.jwtDecoder`).

## Design notes

- **Credential format identifiers**: OID4VCI 1.0's published spec text uses `vc+sd-jwt` for SD-JWT VC
  (an earlier SD-JWT VC draft's spelling); OpenID4VP 1.1 uses the newer `dc+sd-jwt`. Both refer to the
  same format. Rather than duplicate `oid4vp-core`'s `CredentialFormat` enum with a second,
  oid4vci-specific type, `CredentialFormat.fromIdentifier` in oid4vp-core was extended to also recognize
  `vc+sd-jwt` as an alias for `DC_SD_JWT` — its `@JsonValue` output (what oid4vp itself emits) is
  unchanged, so this project's own Issuer Metadata stays spec-literal (`vc+sd-jwt`) while still sharing
  one format enum with oid4vp end to end.
- **v1 scope**: Pre-Authorized Code grant only (`urn:ietf:params:oauth:grant-type:pre-authorized_code`).
  No external Authorization Server, no Authorization Code Grant/PKCE, no deferred or batch issuance yet.
- **Why there's no `oid4vci-spring-security` module**: unlike OpenID4VP (where validating a `vp_token`
  *is* the authentication act, requiring a custom `AuthenticationProvider`/`AbstractHttpConfigurer`),
  none of OID4VCI's v1 endpoints need a novel authentication mechanism. The Token Endpoint mints a bearer
  token as ordinary business logic; the Credential Endpoint is protected by a standard OAuth2 bearer
  access token, which Spring Security's built-in `oauth2ResourceServer()` already solves.
