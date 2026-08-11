package com.darkedges.oid4vci.core.authorize;

import com.darkedges.oid4vci.core.token.AuthorizationDetail;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An Authorization Request (RFC 6749 Section 4.1.1, as used by OID4VCI 1.0 Section 5) — transported as
 * query parameters on a {@code GET} to the Authorization Endpoint.
 *
 * <p>{@code redirectUri} is required to already be a validated, absolute {@link URI} by the time this is
 * constructed: unlike every other field here, an invalid/missing {@code redirect_uri} means the
 * Authorization Endpoint must NOT redirect the error back to the client at all (RFC 6749 Section 4.1.2.1)
 * — the web layer checks that itself before calling {@link #fromQueryParams}, rather than this type
 * throwing an exception that would otherwise look the same as every other validation failure here (all
 * of which DO redirect).
 *
 * @param responseType         REQUIRED — must be {@code "code"}; this issuer implements nothing else.
 * @param clientId              REQUIRED.
 * @param redirectUri           REQUIRED, pre-validated by the caller (see above).
 * @param state                 RECOMMENDED — echoed back on both the success and error redirect.
 * @param codeChallenge         RFC 7636 PKCE — required by this issuer (see
 *                              {@code AuthorizationEndpointController}).
 * @param codeChallengeMethod   RFC 7636 PKCE — only {@code S256} is accepted.
 * @param authorizationDetails  RFC 9396 Rich Authorization Requests, {@code type: "openid_credential"}
 *                              entries — which credential configuration(s) this request is for. Takes
 *                              priority over {@code scopes} when both are present (RAR is more specific).
 * @param scopes                RFC 6749 Section 3.3 — space-delimited {@code scope} parameter, split into
 *                              its individual scope-tokens. HAIP Section 4.3 mandates Wallets use this
 *                              instead of {@code authorization_details}; empty when the client sent
 *                              neither (the issuer then falls back to every configuration it supports,
 *                              same default {@code oid4vci-demo-issuer}'s offer-seeding endpoint already
 *                              uses) — see {@code AuthorizationEndpointController}.
 */
public record AuthorizationRequest(
        String responseType,
        String clientId,
        URI redirectUri,
        Optional<String> state,
        Optional<String> codeChallenge,
        Optional<String> codeChallengeMethod,
        List<AuthorizationDetail> authorizationDetails,
        List<String> scopes) {

    public AuthorizationRequest {
        if (redirectUri == null) {
            throw new IllegalArgumentException("redirect_uri is required");
        }
        responseType = responseType == null ? "" : responseType;
        state = state == null ? Optional.empty() : state;
        codeChallenge = codeChallenge == null ? Optional.empty() : codeChallenge;
        codeChallengeMethod = codeChallengeMethod == null ? Optional.empty() : codeChallengeMethod;
        authorizationDetails = authorizationDetails == null ? List.of() : List.copyOf(authorizationDetails);
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
    }

    /** Parses every field except {@code redirect_uri} (already validated and supplied by the caller) from
     * the request's query parameters. Throws {@link IllegalArgumentException} — with a message safe to
     * surface as {@code error_description} on an {@code error=invalid_request} redirect — if
     * {@code authorization_details} is present but not valid JSON. */
    public static AuthorizationRequest fromQueryParams(Map<String, String> params, URI redirectUri, ObjectMapper mapper) {
        String responseType = params.get("response_type");
        String clientId = params.get("client_id");
        Optional<String> state = Optional.ofNullable(params.get("state"));
        Optional<String> codeChallenge = Optional.ofNullable(params.get("code_challenge"));
        Optional<String> codeChallengeMethod = Optional.ofNullable(params.get("code_challenge_method"));
        List<AuthorizationDetail> authorizationDetails = parseAuthorizationDetails(params.get("authorization_details"), mapper);
        List<String> scopes = parseScopes(params.get("scope"));
        return new AuthorizationRequest(
                responseType, clientId, redirectUri, state, codeChallenge, codeChallengeMethod, authorizationDetails, scopes);
    }

    private static List<String> parseScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }
        return List.of(scope.trim().split("\\s+"));
    }

    private static List<AuthorizationDetail> parseAuthorizationDetails(String json, ObjectMapper mapper) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        JsonNode array;
        try {
            array = mapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("authorization_details is not valid JSON", e);
        }
        if (!array.isArray()) {
            throw new IllegalArgumentException("authorization_details must be a JSON array");
        }
        List<AuthorizationDetail> details = new ArrayList<>();
        for (JsonNode node : array) {
            if (!AuthorizationDetail.TYPE.equals(node.path("type").asText(null))) {
                continue;
            }
            String credentialConfigurationId = node.path("credential_configuration_id").asText(null);
            if (credentialConfigurationId == null || credentialConfigurationId.isBlank()) {
                throw new IllegalArgumentException("authorization_details entry is missing credential_configuration_id");
            }
            details.add(new AuthorizationDetail(credentialConfigurationId, Optional.empty()));
        }
        return details;
    }
}
