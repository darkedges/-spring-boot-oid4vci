package com.darkedges.oid4vci.issuer;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link PushedAuthorizationRequestStore}. Mirrors {@link InMemoryAuthorizationCodeStore}. */
public final class InMemoryPushedAuthorizationRequestStore implements PushedAuthorizationRequestStore {

    private final Map<String, PushedAuthorizationRequestEntry> entries = new ConcurrentHashMap<>();

    @Override
    public void save(String requestUri, PushedAuthorizationRequestEntry entry) {
        entries.put(requestUri, entry);
    }

    @Override
    public Optional<PushedAuthorizationRequestEntry> consume(String requestUri) {
        return Optional.ofNullable(entries.remove(requestUri));
    }
}
