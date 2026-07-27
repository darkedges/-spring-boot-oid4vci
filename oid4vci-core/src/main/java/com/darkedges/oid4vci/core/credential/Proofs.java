package com.darkedges.oid4vci.core.credential;

import java.util.List;
import java.util.Optional;

/**
 * A Credential Request's {@code proofs} object (OID4VCI 1.0, Section 8.2) — keyed by proof type, each
 * value an array (batch issuance sends multiple JWTs, one key pair per credential instance requested;
 * v1 only ever sends a single-element array, but the shape is always an array per spec).
 *
 * @param jwt OPTIONAL — present for the {@code jwt} proof type (the only one this project builds/verifies).
 */
public record Proofs(Optional<List<String>> jwt) {

    public Proofs {
        jwt = jwt == null ? Optional.empty() : jwt.map(List::copyOf);
    }
}
