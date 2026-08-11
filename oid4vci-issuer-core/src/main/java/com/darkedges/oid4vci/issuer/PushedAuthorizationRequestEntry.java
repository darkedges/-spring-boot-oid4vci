package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.authorize.AuthorizationRequest;

import java.time.Instant;

/** A previously-pushed (RFC 9126) Authorization Request, keyed by its {@code request_uri}, plus when it
 * expires — {@link AuthorizationRequest} itself carries every field needed to resume authorization once
 * a client presents that {@code request_uri} back to the Authorization Endpoint. */
public record PushedAuthorizationRequestEntry(AuthorizationRequest request, Instant expiresAt) {

    public PushedAuthorizationRequestEntry {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
    }
}
