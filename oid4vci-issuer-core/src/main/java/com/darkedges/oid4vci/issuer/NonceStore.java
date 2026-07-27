package com.darkedges.oid4vci.issuer;

import java.time.Instant;

/** Where issued-but-not-yet-consumed {@code c_nonce} values live. */
public interface NonceStore {

    void save(String nonce, Instant expiresAt);

    /** Single-use: returns {@code true} exactly once for a given nonce (if it was saved and hasn't
     * expired), removing it either way so a replayed nonce is always rejected. */
    boolean consume(String nonce, Instant now);
}
