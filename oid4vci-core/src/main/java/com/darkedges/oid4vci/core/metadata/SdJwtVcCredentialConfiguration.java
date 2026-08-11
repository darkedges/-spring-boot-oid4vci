package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * {@code credential_configurations_supported} entry for a {@code dc+sd-jwt} (SD-JWT VC) credential
 * configuration (OID4VCI 1.0 Final, Appendix A.3). {@link CredentialConfiguration#format()} always
 * returns {@link CredentialFormat#DC_SD_JWT} — the same enum constant oid4vp-core's DCQL model uses.
 *
 * @param vct REQUIRED — the credential type identifier.
 */
public record SdJwtVcCredentialConfiguration(
        String vct,
        List<ClaimDescription> claims,
        Map<ProofType, ProofTypeSupported> proofTypesSupported,
        List<String> credentialSigningAlgValuesSupported,
        List<String> cryptographicBindingMethodsSupported,
        Optional<String> scope) implements CredentialConfiguration {

    /**
     * The literal {@code format} value {@link CredentialIssuerMetadataWriter} must emit for this
     * configuration — {@code "dc+sd-jwt"}, the OID4VCI 1.0 Final identifier (an earlier draft used
     * {@code "vc+sd-jwt"}; a previous version of this constant kept that pre-final spelling, which the
     * OpenID Conformance Suite's own JSON Schema and {@code VCICheckForOldSdJwtFormatInCredentialConfigurations}
     * check both flag as stale — confirmed live against a real conformance run). {@link CredentialFormat#fromIdentifier}
     * still accepts the old {@code "vc+sd-jwt"} spelling on read, for interop with issuers that haven't
     * updated yet (see {@code ReactorScaffoldTest}); this constant controls only what this project itself
     * writes.
     */
    public static final String WIRE_FORMAT = CredentialFormat.DC_SD_JWT.identifier();

    public SdJwtVcCredentialConfiguration {
        if (vct == null || vct.isBlank()) {
            throw new IllegalArgumentException("vct is required");
        }
        claims = CredentialConfiguration.defaultedClaims(claims);
        proofTypesSupported = CredentialConfiguration.defaultedProofTypes(proofTypesSupported);
        credentialSigningAlgValuesSupported = CredentialConfiguration.defaultedAlgs(credentialSigningAlgValuesSupported);
        cryptographicBindingMethodsSupported = CredentialConfiguration.defaultedBindingMethods(cryptographicBindingMethodsSupported);
        scope = CredentialConfiguration.defaultedScope(scope);
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    /**
     * Resolves {@link #vct()} against {@code baseUrl} — the same per-request base URL every other
     * endpoint URL in this issuer's metadata is built from (see {@code RequestBaseUrl}) — when it's
     * issuer-relative (starts with {@code /}), so its SD-JWT VC Type Metadata document (draft-ietf-oauth-sd-jwt-vc
     * Section 6, fetched by a real HTTP GET straight to the {@code vct} URI) stays reachable regardless
     * of which hostname a client actually used to reach this issuer, rather than a domain baked in at
     * config time. An already-absolute {@code vct} (or a non-URI type identifier, per spec both are
     * valid) is returned unchanged.
     */
    public String resolvedVct(String baseUrl) {
        return vct.startsWith("/") ? baseUrl + vct : vct;
    }
}
