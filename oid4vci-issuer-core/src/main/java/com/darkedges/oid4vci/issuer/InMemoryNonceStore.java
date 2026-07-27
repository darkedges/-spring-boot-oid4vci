package com.darkedges.oid4vci.issuer;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link NonceStore} — see {@link InMemoryPreAuthorizedCodeStore}'s Javadoc for why
 * this lives here rather than in a separate autoconfiguration-only module. */
public final class InMemoryNonceStore implements NonceStore {

    private final Map<String, Instant> expiryByNonce = new ConcurrentHashMap<>();

    @Override
    public void save(String nonce, Instant expiresAt) {
        expiryByNonce.put(nonce, expiresAt);
    }

    @Override
    public boolean consume(String nonce, Instant now) {
        Instant expiresAt = expiryByNonce.remove(nonce);
        return expiresAt != null && expiresAt.isAfter(now);
    }
}
