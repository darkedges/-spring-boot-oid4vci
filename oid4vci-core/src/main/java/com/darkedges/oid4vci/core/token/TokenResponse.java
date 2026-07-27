package com.darkedges.oid4vci.core.token;

import java.util.List;
import java.util.Optional;

/**
 * A successful Token Response (OID4VCI 1.0, Section 6.2 — extends RFC 6749's Access Token Response).
 *
 * @param accessToken           REQUIRED.
 * @param tokenType             REQUIRED, e.g. {@code "Bearer"}.
 * @param expiresIn             OPTIONAL, seconds.
 * @param authorizationDetails  OPTIONAL — present when the issuer scopes the token to specific
 *                              configurations/identifiers rather than everything the redeemed code
 *                              authorized.
 */
public record TokenResponse(
        String accessToken, String tokenType, Optional<Long> expiresIn, Optional<List<AuthorizationDetail>> authorizationDetails) {

    public TokenResponse {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("access_token is required");
        }
        if (tokenType == null || tokenType.isBlank()) {
            throw new IllegalArgumentException("token_type is required");
        }
        expiresIn = expiresIn == null ? Optional.empty() : expiresIn;
        authorizationDetails = authorizationDetails == null ? Optional.empty() : authorizationDetails.map(List::copyOf);
    }
}
