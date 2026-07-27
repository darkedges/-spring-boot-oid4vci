package com.darkedges.oid4vci.issuer;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link IssuedAccessTokenClaimsStore} — see
 * {@link InMemoryPreAuthorizedCodeStore}'s Javadoc for why this lives here rather than in a separate
 * autoconfiguration-only module. */
public final class InMemoryIssuedAccessTokenClaimsStore implements IssuedAccessTokenClaimsStore {

    private final Map<String, Map<String, String>> claimsBySubject = new ConcurrentHashMap<>();

    @Override
    public void save(String subject, Map<String, String> claims) {
        claimsBySubject.put(subject, Map.copyOf(claims));
    }

    @Override
    public Optional<Map<String, String>> find(String subject) {
        return Optional.ofNullable(claimsBySubject.get(subject));
    }
}
