package com.darkedges.oid4vci.demo.issuer;

import java.time.Instant;
import java.util.Optional;

/**
 * One identity-proofing round trip: created when a Wallet asks to be proofed, completed when the
 * proofing service reports a passing result, and read once by the Wallet to collect its offer.
 *
 * <p><strong>Deliberately holds no passport data.</strong> When a result arrives, the claims go
 * straight into the {@code PreAuthorizedCodeSession} keyed by the pre-authorized code, and this
 * session keeps only the resulting Credential Offer — which carries the code and nothing else
 * identifying. So the PII lives in exactly one place, behind a single-use code, instead of being
 * copied into a second store with its own lifetime and its own eviction bug waiting to happen.
 *
 * <p>{@code retrievalSecret} is the reason a session id alone cannot collect a credential. The id
 * travels to the proofing app through an Android custom-scheme deep link, and any app on the device
 * may register the same scheme — so the id must be treated as observable by an attacker. The secret
 * is returned only to the Wallet that created the session and never leaves it, so intercepting the
 * link yields something that cannot be redeemed.
 */
public record ProofingSession(
        String id,
        String retrievalSecret,
        Status status,
        Optional<String> credentialOffer,
        Optional<String> failureReason,
        Instant expiresAt) {

    public enum Status {
        /** Created; the user is somewhere in the proofing app, or has abandoned it. */
        PENDING,
        /** Proofing passed and an offer is waiting to be collected. */
        READY,
        /** Proofing ran and did not pass. Terminal: there is nothing to collect. */
        FAILED
    }

    public ProofingSession {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id is required");
        }
        if (retrievalSecret == null || retrievalSecret.isBlank()) {
            throw new IllegalArgumentException("retrievalSecret is required");
        }
        if (status == null) {
            throw new IllegalArgumentException("status is required");
        }
        credentialOffer = credentialOffer == null ? Optional.empty() : credentialOffer;
        failureReason = failureReason == null ? Optional.empty() : failureReason;
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
        if (status == Status.READY && credentialOffer.isEmpty()) {
            throw new IllegalArgumentException("a READY session must carry a credential offer");
        }
    }

    public static ProofingSession pending(String id, String retrievalSecret, Instant expiresAt) {
        return new ProofingSession(id, retrievalSecret, Status.PENDING, Optional.empty(), Optional.empty(), expiresAt);
    }

    public ProofingSession ready(String credentialOffer) {
        return new ProofingSession(id, retrievalSecret, Status.READY, Optional.of(credentialOffer), Optional.empty(), expiresAt);
    }

    public ProofingSession failed(String reason) {
        return new ProofingSession(id, retrievalSecret, Status.FAILED, Optional.empty(), Optional.of(reason), expiresAt);
    }

    public boolean isExpired(Instant now) {
        return expiresAt.isBefore(now);
    }
}
