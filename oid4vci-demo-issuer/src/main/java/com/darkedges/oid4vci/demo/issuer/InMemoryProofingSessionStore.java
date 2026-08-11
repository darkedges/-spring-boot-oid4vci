package com.darkedges.oid4vci.demo.issuer;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in-memory {@link ProofingSessionStore}, following {@code InMemoryPreAuthorizedCodeStore}.
 *
 * <p>Unlike that one, this evicts. {@code InMemoryPreAuthorizedCodeStore} can get away with growing
 * for ever because a redeemed code is removed on read and an unredeemed one is small. A proofing
 * session left behind holds a Credential Offer whose pre-authorized code still points at real
 * passport claims, so an abandoned session is an identity document sitting in memory until the
 * process restarts.
 *
 * <p>Eviction is driven by the caller (see {@code ProofingController}) rather than a scheduler: it
 * needs no thread, and what matters is that growth is bounded, not the precise moment of removal. An
 * expired entry is already invisible to {@link #find} before it is removed, so a delay in collecting
 * it cannot make one usable.
 */
public final class InMemoryProofingSessionStore implements ProofingSessionStore {

    private final Map<String, ProofingSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void save(ProofingSession session) {
        sessions.put(session.id(), session);
    }

    @Override
    public Optional<ProofingSession> find(String id, Instant now) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.get(id)).filter(session -> !session.isExpired(now));
    }

    @Override
    public void evictExpired(Instant now) {
        sessions.values().removeIf(session -> session.isExpired(now));
    }
}
