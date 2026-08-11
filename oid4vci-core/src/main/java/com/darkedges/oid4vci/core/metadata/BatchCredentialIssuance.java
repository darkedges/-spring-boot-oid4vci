package com.darkedges.oid4vci.core.metadata;

/**
 * The Credential Issuer Metadata's {@code batch_credential_issuance} object (OID4VCI 1.0 Final, Section
 * 12.2.4) — its presence advertises that the Credential Endpoint accepts more than one key proof per
 * Credential Request (one issued Credential per proof, all sharing the same Credential Dataset); its
 * absence means a Credential Request may carry at most one proof.
 *
 * @param batchSize REQUIRED, MUST be 2 or greater — the maximum number of entries the {@code proofs}
 *                  parameter of a Credential Request may contain.
 */
public record BatchCredentialIssuance(int batchSize) {

    public BatchCredentialIssuance {
        if (batchSize < 2) {
            throw new IllegalArgumentException("batch_size must be 2 or greater");
        }
    }
}
