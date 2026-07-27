package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

/** Issues and consumes single-use {@code c_nonce} values (Nonce Endpoint / proof-of-possession binding). */
public final class NonceService {

    private static final int TOKEN_BYTES = 32; // 256 bits, matching oid4vp's own nonce/state generation

    private final NonceStore store;
    private final Clock clock;
    private final Duration ttl;
    private final SecureRandom random = new SecureRandom();

    public NonceService(NonceStore store, Clock clock, Duration ttl) {
        this.store = store;
        this.clock = clock;
        this.ttl = ttl;
    }

    public String issue() {
        String nonce = randomUrlSafeToken();
        store.save(nonce, clock.instant().plus(ttl));
        return nonce;
    }

    /** @throws Oid4vciException with {@link Oid4vciErrorCode#INVALID_NONCE} if the nonce is unknown,
     * already consumed, or expired. */
    public void requireValid(String nonce) {
        if (!store.consume(nonce, clock.instant())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_NONCE, "unknown, already-used, or expired c_nonce");
        }
    }

    private String randomUrlSafeToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
