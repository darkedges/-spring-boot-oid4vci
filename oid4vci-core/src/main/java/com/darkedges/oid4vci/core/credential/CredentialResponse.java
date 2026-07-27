package com.darkedges.oid4vci.core.credential;

import java.util.List;
import java.util.Optional;

/**
 * A Credential Response (OID4VCI 1.0, Section 8.3). Exactly one of {@code credentials}/
 * {@code transactionId} is present: the former on immediate issuance — an array of {@link IssuedCredential}
 * wrapper objects, one per key the Wallet supplied via the request's {@code proofs} (v1 only ever sends
 * a single one); the latter for deferred issuance, which no v1 code path produces yet (modeled so a
 * response carrying one still parses).
 */
public record CredentialResponse(Optional<List<IssuedCredential>> credentials, Optional<String> transactionId) {

    public CredentialResponse {
        credentials = credentials == null ? Optional.empty() : credentials.map(List::copyOf);
        transactionId = transactionId == null ? Optional.empty() : transactionId;
        if (credentials.isEmpty() && transactionId.isEmpty()) {
            throw new IllegalArgumentException("exactly one of credentials/transaction_id is required");
        }
        if (credentials.isPresent() && transactionId.isPresent()) {
            throw new IllegalArgumentException("credentials and transaction_id are mutually exclusive");
        }
    }
}
