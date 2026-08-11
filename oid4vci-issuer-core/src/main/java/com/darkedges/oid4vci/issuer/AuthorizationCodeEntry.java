package com.darkedges.oid4vci.issuer;

import java.net.URI;
import java.util.Optional;

/**
 * What an issued-but-not-yet-redeemed authorization code binds together: the {@link PreAuthorizedCodeSession}
 * it will hand back once redeemed (reused as-is — the two grants produce an identical shape: which
 * credential configurations, what claim values, when it expires; only how the code was obtained differs),
 * plus the RFC 6749/7636 fields the Token Endpoint must revalidate on redemption — the exact
 * {@code redirect_uri} the authorization request used, and the PKCE {@code code_challenge}/
 * {@code code_challenge_method} the eventual {@code code_verifier} must hash to.
 */
public record AuthorizationCodeEntry(
        PreAuthorizedCodeSession session, URI redirectUri,
        Optional<String> codeChallenge, Optional<String> codeChallengeMethod) {

    public AuthorizationCodeEntry {
        if (session == null) {
            throw new IllegalArgumentException("session is required");
        }
        if (redirectUri == null) {
            throw new IllegalArgumentException("redirectUri is required");
        }
        codeChallenge = codeChallenge == null ? Optional.empty() : codeChallenge;
        codeChallengeMethod = codeChallengeMethod == null ? Optional.empty() : codeChallengeMethod;
    }
}
