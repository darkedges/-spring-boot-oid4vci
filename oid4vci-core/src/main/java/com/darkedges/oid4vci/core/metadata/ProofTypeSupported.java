package com.darkedges.oid4vci.core.metadata;

import java.util.List;

/**
 * The value side of a {@code proof_types_supported} map entry (OID4VCI 1.0, Appendix E) — confirmed via
 * two independent real-world Credential Issuer Metadata documents (Android Developers' hardware-backed
 * attestation docs, GOV.UK Wallet's issuer metadata docs) to be an object keyed by proof type name (e.g.
 * {@code "jwt"}), not a plain array of type-name strings.
 *
 * @param proofSigningAlgValuesSupported REQUIRED non-empty — which signing algorithms a proof of this
 *                                       type may use.
 */
public record ProofTypeSupported(List<String> proofSigningAlgValuesSupported) {

    public ProofTypeSupported {
        if (proofSigningAlgValuesSupported == null || proofSigningAlgValuesSupported.isEmpty()) {
            throw new IllegalArgumentException("proof_signing_alg_values_supported must be a non-empty array");
        }
        proofSigningAlgValuesSupported = List.copyOf(proofSigningAlgValuesSupported);
    }
}
