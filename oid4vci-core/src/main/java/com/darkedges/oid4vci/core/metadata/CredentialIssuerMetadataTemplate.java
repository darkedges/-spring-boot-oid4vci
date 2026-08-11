package com.darkedges.oid4vci.core.metadata;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The host-independent shape of a Credential Issuer Metadata document: everything except the base URL
 * itself. A Credential Issuer typically has no single fixed public base URL baked into its own config —
 * it's whatever scheme/host/port a client actually used to reach it (behind a reverse proxy, a Docker
 * network alias, or a public tunnel, these can legitimately differ) — so {@link #resolve} builds the full
 * {@link CredentialIssuerMetadata} document fresh for each request, from that request's own resolved base
 * URL, rather than one baked in once at startup.
 */
public record CredentialIssuerMetadataTemplate(
        String credentialEndpointPath,
        Optional<String> nonceEndpointPath,
        Map<String, CredentialConfiguration> credentialConfigurationsSupported,
        Optional<BatchCredentialIssuance> batchCredentialIssuance) {

    public CredentialIssuerMetadataTemplate {
        if (credentialEndpointPath == null || credentialEndpointPath.isBlank()) {
            throw new IllegalArgumentException("credentialEndpointPath is required");
        }
        nonceEndpointPath = nonceEndpointPath == null ? Optional.empty() : nonceEndpointPath;
        if (credentialConfigurationsSupported == null || credentialConfigurationsSupported.isEmpty()) {
            throw new IllegalArgumentException("credential_configurations_supported must be a non-empty object");
        }
        credentialConfigurationsSupported = Map.copyOf(credentialConfigurationsSupported);
        batchCredentialIssuance = batchCredentialIssuance == null ? Optional.empty() : batchCredentialIssuance;
    }

    /** As the canonical constructor, but with no {@code batch_credential_issuance} — for the many
     * existing call sites (tests) that don't care about batch issuance. */
    public CredentialIssuerMetadataTemplate(
            String credentialEndpointPath, Optional<String> nonceEndpointPath,
            Map<String, CredentialConfiguration> credentialConfigurationsSupported) {
        this(credentialEndpointPath, nonceEndpointPath, credentialConfigurationsSupported, Optional.empty());
    }

    /** Builds the full metadata document as it should be advertised to a client that reached this issuer
     * at {@code baseUrl} (no trailing slash, e.g. {@code https://issuer.zkp.au}). Also resolves every
     * {@link SdJwtVcCredentialConfiguration}'s issuer-relative {@code vct} against this same {@code baseUrl}
     * (see {@link SdJwtVcCredentialConfiguration#resolvedVct}) — since {@code CredentialController} always
     * looks the configuration it hands to a {@code CredentialIssuanceService} back up from a freshly
     * resolved document, this is also what ends up embedded in the issued credential's own {@code vct}
     * claim, so the two never disagree. */
    public CredentialIssuerMetadata resolve(String baseUrl) {
        Map<String, CredentialConfiguration> resolvedConfigurations = new LinkedHashMap<>();
        credentialConfigurationsSupported.forEach(
                (id, configuration) -> resolvedConfigurations.put(id, resolveConfiguration(configuration, baseUrl)));
        return new CredentialIssuerMetadata(
                URI.create(baseUrl),
                URI.create(baseUrl + credentialEndpointPath),
                nonceEndpointPath.map(path -> URI.create(baseUrl + path)),
                Optional.empty(),
                List.of(),
                resolvedConfigurations,
                batchCredentialIssuance);
    }

    private static CredentialConfiguration resolveConfiguration(CredentialConfiguration configuration, String baseUrl) {
        if (configuration instanceof SdJwtVcCredentialConfiguration sdJwt) {
            return new SdJwtVcCredentialConfiguration(
                    sdJwt.resolvedVct(baseUrl), sdJwt.claims(), sdJwt.proofTypesSupported(),
                    sdJwt.credentialSigningAlgValuesSupported(), sdJwt.cryptographicBindingMethodsSupported(), sdJwt.scope());
        }
        return configuration;
    }
}
