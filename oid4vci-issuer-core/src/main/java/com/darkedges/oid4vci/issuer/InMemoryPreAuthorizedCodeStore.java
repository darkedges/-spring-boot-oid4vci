package com.darkedges.oid4vci.issuer;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in-memory {@link PreAuthorizedCodeStore}. Lives here (not deferred to a separate
 * autoconfiguration-only module) because — unlike oid4vp, which has a dedicated
 * {@code oid4vp-spring-security} module for this kind of thing — oid4vci has no Spring Security
 * integration module at all (see the project README); the closest real precedent is
 * {@code oid4vp-spring-security} itself co-locating its {@code InMemoryOid4vp*Repository} default
 * implementations right next to the interfaces they implement, which is what this does too.
 */
public final class InMemoryPreAuthorizedCodeStore implements PreAuthorizedCodeStore {

    private final Map<String, PreAuthorizedCodeSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void save(String code, PreAuthorizedCodeSession session) {
        sessions.put(code, session);
    }

    @Override
    public Optional<PreAuthorizedCodeSession> consume(String code) {
        return Optional.ofNullable(sessions.remove(code));
    }
}
