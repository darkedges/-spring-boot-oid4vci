package com.darkedges.oid4vci.core.metadata;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Credential Issuer Metadata document served at
 * {@code /.well-known/openid-credential-issuer} (OID4VCI 1.0, Section 12).
 *
 * @param credentialIssuer      REQUIRED — the Credential Issuer's identifier.
 * @param credentialEndpoint    REQUIRED.
 * @param nonceEndpoint         OPTIONAL — required to be present if any advertised
 *                              {@code credential_configurations_supported} entry supports the
 *                              {@code jwt} proof type and the issuer wants to require {@code c_nonce}
 *                              binding (this model doesn't enforce that cross-field constraint).
 * @param deferredCredentialEndpoint OPTIONAL — modeled so metadata referencing it still parses; no v1
 *                              code path issues a deferred (202 + {@code transaction_id}) response yet.
 * @param authorizationServers  OPTIONAL — if absent, the Credential Issuer is its own Authorization
 *                              Server (the only case a v1 Issuer needs, since it self-issues its own
 *                              pre-authorized codes).
 * @param credentialConfigurationsSupported REQUIRED non-empty, keyed by configuration id.
 */
public record CredentialIssuerMetadata(
        URI credentialIssuer,
        URI credentialEndpoint,
        Optional<URI> nonceEndpoint,
        Optional<URI> deferredCredentialEndpoint,
        List<URI> authorizationServers,
        Map<String, CredentialConfiguration> credentialConfigurationsSupported) {

    public CredentialIssuerMetadata {
        if (credentialIssuer == null) {
            throw new IllegalArgumentException("credential_issuer is required");
        }
        if (credentialEndpoint == null) {
            throw new IllegalArgumentException("credential_endpoint is required");
        }
        if (credentialConfigurationsSupported == null || credentialConfigurationsSupported.isEmpty()) {
            throw new IllegalArgumentException("credential_configurations_supported must be a non-empty object");
        }
        nonceEndpoint = nonceEndpoint == null ? Optional.empty() : nonceEndpoint;
        deferredCredentialEndpoint = deferredCredentialEndpoint == null ? Optional.empty() : deferredCredentialEndpoint;
        authorizationServers = authorizationServers == null ? List.of() : List.copyOf(authorizationServers);
        credentialConfigurationsSupported = Map.copyOf(credentialConfigurationsSupported);
    }
}
