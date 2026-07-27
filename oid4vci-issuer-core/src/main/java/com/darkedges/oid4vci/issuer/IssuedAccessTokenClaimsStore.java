package com.darkedges.oid4vci.issuer;

import java.util.Map;
import java.util.Optional;

/**
 * Associates an access token's {@code subject} (see {@link AccessTokenService.IssuedAccessToken}) with
 * the claim values a Credential Request presenting that token is authorized to have issued into a
 * credential. A stand-in for what would be a real user/session profile lookup in a production issuer;
 * here it exists purely to bridge token-minting time (where the claim values are known, from the
 * redeemed {@link PreAuthorizedCodeSession}) to credential-request time (where they're needed again,
 * looked up by the authenticated token's subject rather than re-derived from anywhere).
 */
public interface IssuedAccessTokenClaimsStore {

    void save(String subject, Map<String, String> claims);

    Optional<Map<String, String>> find(String subject);
}
