package com.darkedges.oid4vci.issuer;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link AuthorizationCodeStore}. Mirrors {@link InMemoryPreAuthorizedCodeStore}. */
public final class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {

    private final Map<String, AuthorizationCodeEntry> entries = new ConcurrentHashMap<>();

    @Override
    public void save(String code, AuthorizationCodeEntry entry) {
        entries.put(code, entry);
    }

    @Override
    public Optional<AuthorizationCodeEntry> consume(String code) {
        return Optional.ofNullable(entries.remove(code));
    }
}
