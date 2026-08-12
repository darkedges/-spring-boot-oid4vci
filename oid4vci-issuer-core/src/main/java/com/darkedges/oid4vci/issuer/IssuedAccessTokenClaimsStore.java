package com.darkedges.oid4vci.issuer;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Associates an access token's {@code subject} (see {@link AccessTokenService.IssuedAccessToken}) with
 * the claim values a Credential Request presenting that token is authorized to have issued into a
 * credential. A stand-in for what would be a real user/session profile lookup in a production issuer;
 * here it exists purely to bridge token-minting time (where the claim values are known, from the
 * redeemed {@link PreAuthorizedCodeSession}) to credential-request time (where they're needed again,
 * looked up by the authenticated token's subject rather than re-derived from anywhere).
 *
 * <p><strong>Entries expire.</strong> {@code save} takes the instant its access token stops being
 * valid, and an implementation must treat anything past it as absent. The claims are unusable after
 * that point anyway — nothing can present an expired token to redeem them — so keeping them buys
 * nothing and costs everything: with a real issuer these are somebody's name, date of birth and
 * passport number, and a store that only ever grows is a store that accumulates identity documents
 * until the process restarts. That was true here from the day this was written and harmless only
 * while the claims said {@code Jane Doe}.
 */
public interface IssuedAccessTokenClaimsStore {

    /**
     * @param expiresAt when the access token naming {@code subject} stops being valid. The entry must
     *                  not be readable after this instant, and an implementation should take the
     *                  opportunity to drop other expired entries.
     */
    void save(String subject, Map<String, String> claims, Instant expiresAt);

    /** Returns empty for an unknown subject, and for one whose entry has expired by {@code now}. */
    Optional<Map<String, String>> find(String subject, Instant now);
}
