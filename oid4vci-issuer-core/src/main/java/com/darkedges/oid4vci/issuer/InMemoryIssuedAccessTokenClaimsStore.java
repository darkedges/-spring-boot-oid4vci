package com.darkedges.oid4vci.issuer;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link IssuedAccessTokenClaimsStore} — see
 * {@link InMemoryPreAuthorizedCodeStore}'s Javadoc for why this lives here rather than in a separate
 * autoconfiguration-only module.
 *
 * <p>Unlike that one, this evicts, and the difference is not stylistic. A pre-authorized code is
 * removed when it is redeemed, so that map drains itself; entries here are never read a second time
 * by anything and were never removed at all. Every credential issued left its claim values in memory
 * for the life of the process — fine for {@code Jane Doe}, and an accumulating pile of passport data
 * once a real issuer uses it.
 *
 * <p>Eviction is driven by {@link #save}, not a scheduler: it needs no thread, and what matters is
 * that the map stays bounded rather than the precise moment an entry goes. Expired entries are
 * already invisible to {@link #find} before they are removed, so the lag cannot make one usable. */
public final class InMemoryIssuedAccessTokenClaimsStore implements IssuedAccessTokenClaimsStore {

    private record Entry(Map<String, String> claims, Instant expiresAt) {}

    private final Map<String, Entry> entriesBySubject = new ConcurrentHashMap<>();
    private final Clock clock;

    /** Uses the system clock. The no-arg form keeps every existing construction site working. */
    public InMemoryIssuedAccessTokenClaimsStore() {
        this(Clock.systemUTC());
    }

    /**
     * A clock, because sweeping needs a "now" and {@code save} is only told when the <em>new</em>
     * entry expires.
     *
     * Sweeping only on {@link #find} would leave the worst case unbounded: a token minted and never
     * redeemed is never looked up, and those are precisely the entries nobody collects and everybody
     * forgets — an abandoned flow leaving passport claims behind indefinitely.
     */
    public InMemoryIssuedAccessTokenClaimsStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void save(String subject, Map<String, String> claims, Instant expiresAt) {
        // Swept before the put, so a burst of issuance cannot outrun the cleanup it is causing.
        Instant now = clock.instant();
        entriesBySubject.values().removeIf(entry -> !entry.expiresAt().isAfter(now));
        entriesBySubject.put(subject, new Entry(Map.copyOf(claims), expiresAt));
    }

    @Override
    public Optional<Map<String, String>> find(String subject, Instant now) {
        Entry entry = entriesBySubject.get(subject);
        if (entry == null) {
            return Optional.empty();
        }
        if (!entry.expiresAt().isAfter(now)) {
            // Dropped on the way past. Reading an expired entry is the most reliable moment to
            // notice one, and leaving it for a later sweep would keep the claims around longer than
            // anything can use them.
            entriesBySubject.remove(subject, entry);
            return Optional.empty();
        }
        return Optional.of(entry.claims());
    }
}
