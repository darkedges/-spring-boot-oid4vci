package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

import java.util.List;
import java.util.Map;

/**
 * {@code credential_configurations_supported} entry for a {@code vc+sd-jwt} (SD-JWT VC) credential
 * configuration (OID4VCI 1.0, Appendix A.3). {@link CredentialConfiguration#format()} always returns
 * {@link CredentialFormat#DC_SD_JWT} — the same enum constant oid4vp-core's DCQL model uses; see the
 * project README for why the two specs' differing identifier spellings for this format both parse to it.
 *
 * @param vct REQUIRED — the credential type identifier.
 */
public record SdJwtVcCredentialConfiguration(
        String vct,
        List<ClaimDescription> claims,
        Map<ProofType, ProofTypeSupported> proofTypesSupported,
        List<String> credentialSigningAlgValuesSupported,
        List<String> cryptographicBindingMethodsSupported) implements CredentialConfiguration {

    /**
     * The literal {@code format} value {@link CredentialIssuerMetadataWriter} must emit for this
     * configuration — {@code "vc+sd-jwt"}, not {@link #format()}{@code .identifier()} (which is always
     * {@code "dc+sd-jwt"}, oid4vp's own canonical spelling for the shared enum constant). A first draft
     * of the writer used {@code format().identifier()} directly and a round-trip test caught it silently
     * rewriting a spec-correct {@code "vc+sd-jwt"} input into {@code "dc+sd-jwt"} on the way back out.
     */
    public static final String WIRE_FORMAT = "vc+sd-jwt";

    public SdJwtVcCredentialConfiguration {
        if (vct == null || vct.isBlank()) {
            throw new IllegalArgumentException("vct is required");
        }
        claims = CredentialConfiguration.defaultedClaims(claims);
        proofTypesSupported = CredentialConfiguration.defaultedProofTypes(proofTypesSupported);
        credentialSigningAlgValuesSupported = CredentialConfiguration.defaultedAlgs(credentialSigningAlgValuesSupported);
        cryptographicBindingMethodsSupported = CredentialConfiguration.defaultedBindingMethods(cryptographicBindingMethodsSupported);
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }
}
