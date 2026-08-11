package com.darkedges.oid4vci.demo.issuer;

import java.time.Instant;
import java.util.Optional;

/** Where in-flight identity-proofing sessions live between the Wallet's request and its collection. */
public interface ProofingSessionStore {

    void save(ProofingSession session);

    /**
     * Reads a session, treating an expired one as absent.
     *
     * <p>Unlike {@code PreAuthorizedCodeStore#consume}, this does not remove: the Wallet polls while
     * the user is still in the proofing app, so a read has to be repeatable. Single use is enforced
     * one layer down instead, by the pre-authorized code inside the offer — collecting the offer twice
     * yields a code that can still only be redeemed once.
     */
    Optional<ProofingSession> find(String id, Instant now);

    /** Drops expired sessions. Called opportunistically rather than on a timer; see the in-memory
     * implementation for why that is enough here. */
    void evictExpired(Instant now);
}
