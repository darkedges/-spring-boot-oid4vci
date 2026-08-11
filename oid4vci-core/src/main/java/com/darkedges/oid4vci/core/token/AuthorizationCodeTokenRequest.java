package com.darkedges.oid4vci.core.token;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * A Token Request using the {@code authorization_code} grant (RFC 6749 Section 4.1.3, as used by OID4VCI
 * 1.0 Section 6.1) — transported as {@code application/x-www-form-urlencoded}, same convention as
 * {@link PreAuthorizedCodeTokenRequest}.
 *
 * @param code        REQUIRED — the code issued by the Authorization Endpoint.
 * @param redirectUri REQUIRED — must match the {@code redirect_uri} the code was issued for exactly (not
 *                    enforced by this type; the issuer-side service checks that).
 * @param codeVerifier RFC 7636 PKCE — required iff the authorization request that produced this code
 *                     carried a {@code code_challenge} (not enforced by this type).
 */
public record AuthorizationCodeTokenRequest(String code, URI redirectUri, Optional<String> codeVerifier) {

    public AuthorizationCodeTokenRequest {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("code is required");
        }
        if (redirectUri == null) {
            throw new IllegalArgumentException("redirect_uri is required");
        }
        codeVerifier = codeVerifier == null ? Optional.empty() : codeVerifier;
    }

    /** Parses the request from its form-urlencoded fields (already decoded by the web layer), requiring
     * {@code grant_type} to be exactly {@link GrantType#AUTHORIZATION_CODE}. */
    public static AuthorizationCodeTokenRequest fromFormParams(Map<String, String> params) {
        String grantType = params.get("grant_type");
        if (grantType == null || !GrantType.AUTHORIZATION_CODE.value().equals(grantType)) {
            throw new IllegalArgumentException("grant_type must be " + GrantType.AUTHORIZATION_CODE.value());
        }
        String code = params.get("code");
        String redirectUri = params.get("redirect_uri");
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirect_uri is required");
        }
        Optional<String> codeVerifier = Optional.ofNullable(params.get("code_verifier"));
        return new AuthorizationCodeTokenRequest(code, URI.create(redirectUri), codeVerifier);
    }
}
