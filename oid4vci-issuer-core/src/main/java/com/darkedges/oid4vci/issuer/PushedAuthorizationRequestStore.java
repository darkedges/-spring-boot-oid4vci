package com.darkedges.oid4vci.issuer;

import java.util.Optional;

/** Where pushed-but-not-yet-redeemed (RFC 9126) Authorization Requests live. Mirrors
 * {@link AuthorizationCodeStore}. */
public interface PushedAuthorizationRequestStore {

    void save(String requestUri, PushedAuthorizationRequestEntry entry);

    /** Single-use: an implementation must remove the entry on a successful read, so a second Authorization
     * Endpoint request presenting the same {@code request_uri} always sees {@link Optional#empty()}. */
    Optional<PushedAuthorizationRequestEntry> consume(String requestUri);
}
