package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * {@code credential_configurations_supported} entry for an {@code mso_mdoc} credential configuration
 * (OID4VCI 1.0, Appendix A.2).
 *
 * @param doctype REQUIRED — the ISO 18013-5 doctype identifier, e.g. {@code org.iso.18013.5.1.mDL}.
 */
public record MsoMdocCredentialConfiguration(
        String doctype,
        List<ClaimDescription> claims,
        Map<ProofType, ProofTypeSupported> proofTypesSupported,
        List<String> credentialSigningAlgValuesSupported,
        List<String> cryptographicBindingMethodsSupported,
        Optional<String> scope) implements CredentialConfiguration {

    public MsoMdocCredentialConfiguration {
        if (doctype == null || doctype.isBlank()) {
            throw new IllegalArgumentException("doctype is required");
        }
        claims = CredentialConfiguration.defaultedClaims(claims);
        proofTypesSupported = CredentialConfiguration.defaultedProofTypes(proofTypesSupported);
        credentialSigningAlgValuesSupported = CredentialConfiguration.defaultedAlgs(credentialSigningAlgValuesSupported);
        cryptographicBindingMethodsSupported = CredentialConfiguration.defaultedBindingMethods(cryptographicBindingMethodsSupported);
        scope = CredentialConfiguration.defaultedScope(scope);
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.MSO_MDOC;
    }
}
