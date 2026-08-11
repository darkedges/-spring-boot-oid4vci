package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.token.AuthorizationCodeTokenRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Base64;

/** Validates and single-use-consumes an authorization code redemption at the Token Endpoint (RFC 6749
 * Section 4.1.3), including the RFC 7636 PKCE check — mirrors {@link PreAuthorizedCodeService}. */
public final class AuthorizationCodeService {

    private final AuthorizationCodeStore store;
    private final Clock clock;

    public AuthorizationCodeService(AuthorizationCodeStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public PreAuthorizedCodeSession redeem(AuthorizationCodeTokenRequest request) {
        AuthorizationCodeEntry entry = store.consume(request.code())
                .orElseThrow(() -> new Oid4vciException(
                        Oid4vciErrorCode.INVALID_GRANT, "unknown or already-redeemed authorization code"));

        if (entry.session().expiresAt().isBefore(clock.instant())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT, "authorization code has expired");
        }

        if (!entry.redirectUri().equals(request.redirectUri())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT,
                    "redirect_uri does not match the one used in the authorization request");
        }

        if (entry.codeChallenge().isPresent()) {
            String verifier = request.codeVerifier()
                    .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT, "code_verifier is required"));
            if (!entry.codeChallenge().get().equals(computeS256Challenge(verifier))) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT, "code_verifier does not match code_challenge");
            }
        }

        return entry.session();
    }

    private static String computeS256Challenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
