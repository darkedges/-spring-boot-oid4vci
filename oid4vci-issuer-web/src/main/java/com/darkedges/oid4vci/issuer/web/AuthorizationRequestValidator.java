package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.authorize.AuthorizationRequest;

import java.util.Optional;

/** The OAuth-shape checks common to both the Authorization Endpoint's inline flow and the Pushed
 * Authorization Request Endpoint (RFC 9126) — the latter needs to reject a malformed request at push
 * time rather than only discovering the problem once a client later shows up with its {@code request_uri}. */
final class AuthorizationRequestValidator {

    private AuthorizationRequestValidator() {}

    record Error(String error, String description) {}

    static Optional<Error> validate(AuthorizationRequest request) {
        if (request.clientId() == null || request.clientId().isBlank()) {
            return Optional.of(new Error("invalid_request", "client_id is required"));
        }
        if (!"code".equals(request.responseType())) {
            return Optional.of(new Error("unsupported_response_type", "only response_type=code is supported"));
        }
        if (request.codeChallenge().isEmpty() || request.codeChallengeMethod().isEmpty()) {
            return Optional.of(new Error("invalid_request", "code_challenge and code_challenge_method are required"));
        }
        if (!"S256".equals(request.codeChallengeMethod().get())) {
            return Optional.of(new Error("invalid_request", "only code_challenge_method=S256 is supported"));
        }
        return Optional.empty();
    }
}
