package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

import java.util.List;
import java.util.Map;

/**
 * A {@code credential_configurations_supported} map entry (OID4VCI 1.0, Section 12.2 / Appendix A) —
 * sealed on the same {@link CredentialFormat} oid4vp-core's own DCQL model uses, mirroring how
 * {@code CredentialQueryMeta}'s {@code SdJwtVcMeta}/{@code MsoMdocMeta} split by format.
 */
public sealed interface CredentialConfiguration permits SdJwtVcCredentialConfiguration, MsoMdocCredentialConfiguration {

    CredentialFormat format();

    List<ClaimDescription> claims();

    Map<ProofType, ProofTypeSupported> proofTypesSupported();

    List<String> credentialSigningAlgValuesSupported();

    List<String> cryptographicBindingMethodsSupported();

    /** Common validation shared by every format's configuration, factored out since every implementation
     * needs the same non-null defaulting for its shared fields. */
    static List<ClaimDescription> defaultedClaims(List<ClaimDescription> claims) {
        return claims == null ? List.of() : List.copyOf(claims);
    }

    static Map<ProofType, ProofTypeSupported> defaultedProofTypes(Map<ProofType, ProofTypeSupported> proofTypes) {
        return proofTypes == null ? Map.of() : Map.copyOf(proofTypes);
    }

    static List<String> defaultedAlgs(List<String> algs) {
        return algs == null ? List.of() : List.copyOf(algs);
    }

    static List<String> defaultedBindingMethods(List<String> methods) {
        return methods == null ? List.of() : List.copyOf(methods);
    }
}
