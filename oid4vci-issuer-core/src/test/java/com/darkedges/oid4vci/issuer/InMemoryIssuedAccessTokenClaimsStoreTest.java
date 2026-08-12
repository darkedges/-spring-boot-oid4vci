package com.darkedges.oid4vci.issuer;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Expiry in the claims store.
 *
 * Worth its own test because the thing it protects is invisible in every functional path: a store
 * that never evicts issues credentials exactly as correctly as one that does, and the only symptom
 * is that a long-running issuer accumulates the passport details of everyone it has ever served.
 */
class InMemoryIssuedAccessTokenClaimsStoreTest {

    private static final Instant NOW = Instant.parse("2026-08-12T00:00:00Z");
    private static final Map<String, String> CLAIMS = Map.of("family_name", "FITZGERALD");

    private static Clock at(Instant instant) {
        return Clock.fixed(instant, ZoneOffset.UTC);
    }

    @Test
    void findsClaimsWhileTheTokenIsStillValid() {
        InMemoryIssuedAccessTokenClaimsStore store = new InMemoryIssuedAccessTokenClaimsStore(at(NOW));
        store.save("subject-1", CLAIMS, NOW.plus(Duration.ofMinutes(5)));

        assertThat(store.find("subject-1", NOW.plus(Duration.ofMinutes(4)))).contains(CLAIMS);
    }

    @Test
    void forgetsClaimsOnceTheTokenHasExpired() {
        InMemoryIssuedAccessTokenClaimsStore store = new InMemoryIssuedAccessTokenClaimsStore(at(NOW));
        store.save("subject-1", CLAIMS, NOW.plus(Duration.ofMinutes(5)));

        assertThat(store.find("subject-1", NOW.plus(Duration.ofMinutes(6)))).isEmpty();
    }

    @Test
    void treatsTheExpiryInstantItselfAsExpired() {
        // The token is invalid at exactly its exp, so the claims it authorizes are too. Off by one in
        // this direction leaves identity data readable for a moment longer than anything can use it.
        InMemoryIssuedAccessTokenClaimsStore store = new InMemoryIssuedAccessTokenClaimsStore(at(NOW));
        Instant expiry = NOW.plus(Duration.ofMinutes(5));
        store.save("subject-1", CLAIMS, expiry);

        assertThat(store.find("subject-1", expiry)).isEmpty();
    }

    @Test
    void dropsAnExpiredEntryRatherThanMerelyHidingIt() {
        // Hiding it would satisfy every caller and still leave the passport data in memory, which is
        // the entire problem this exists to solve.
        InMemoryIssuedAccessTokenClaimsStore store = new InMemoryIssuedAccessTokenClaimsStore(at(NOW));
        store.save("subject-1", CLAIMS, NOW.plus(Duration.ofMinutes(5)));

        store.find("subject-1", NOW.plus(Duration.ofMinutes(6)));

        // Looking again from *before* the expiry proves the entry is gone rather than filtered: a
        // merely-hidden entry would reappear the moment the clock argument moved back.
        assertThat(store.find("subject-1", NOW.plus(Duration.ofMinutes(1)))).isEmpty();
    }

    @Test
    void sweepsAbandonedEntriesOnTheNextSave() {
        // The worst case, and the reason the store holds a clock at all: a token minted and never
        // redeemed is never looked up, so eviction on read alone would never reach it. Those are
        // exactly the entries nobody collects and everybody forgets.
        MutableClock clock = new MutableClock(NOW);
        InMemoryIssuedAccessTokenClaimsStore store = new InMemoryIssuedAccessTokenClaimsStore(clock);
        store.save("abandoned", CLAIMS, NOW.plus(Duration.ofMinutes(5)));

        clock.advanceTo(NOW.plus(Duration.ofHours(1)));
        store.save("subject-2", CLAIMS, clock.instant().plus(Duration.ofMinutes(5)));

        // Unreadable even when asked from before its expiry, which it could not be if the entry were
        // merely being filtered on the way out rather than removed.
        assertThat(store.find("abandoned", NOW.plus(Duration.ofMinutes(1)))).isEmpty();
        assertThat(store.find("subject-2", clock.instant())).contains(CLAIMS);
    }

    /** A clock that can be moved, since expiry cannot be exercised against a fixed one. */
    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void advanceTo(Instant to) {
            this.instant = to;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
