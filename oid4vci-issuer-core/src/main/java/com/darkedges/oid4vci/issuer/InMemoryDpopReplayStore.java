package com.darkedges.oid4vci.issuer;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link DpopReplayStore} — see {@link InMemoryPreAuthorizedCodeStore}'s Javadoc for
 * why this lives here rather than in a separate autoconfiguration-only module. Expired entries are swept
 * opportunistically on each call rather than via a background task, matching this project's other
 * in-memory stores' scale (a demo/single-instance issuer, not a production deployment). */
public final class InMemoryDpopReplayStore implements DpopReplayStore {

    private final Map<String, Instant> expiryByJti = new ConcurrentHashMap<>();

    @Override
    public boolean recordUse(String jti, Instant now, Instant expiresAt) {
        expiryByJti.values().removeIf(expiry -> !expiry.isAfter(now));
        return expiryByJti.putIfAbsent(jti, expiresAt) == null;
    }
}
