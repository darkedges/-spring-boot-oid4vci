package com.darkedges.oid4vci.issuer;

import java.time.Instant;

/** Anti-replay tracking for DPoP proof {@code jti} values (RFC 9449 Section 4.3: "the server SHOULD
 * reject any DPoP proof in which the jti has been seen before"). */
public interface DpopReplayStore {

    /** Atomically records this {@code jti} as used, expiring the record at {@code expiresAt}. Returns
     * {@code true} if this is the first time it's been seen (the proof is accepted), {@code false} if
     * it's a replay of a still-live record (the proof must be rejected). {@code now} is supplied by the
     * caller rather than read from the system clock — same convention as {@link NonceStore#consume} —
     * so behavior stays deterministic under a fixed test {@link java.time.Clock}. */
    boolean recordUse(String jti, Instant now, Instant expiresAt);
}
