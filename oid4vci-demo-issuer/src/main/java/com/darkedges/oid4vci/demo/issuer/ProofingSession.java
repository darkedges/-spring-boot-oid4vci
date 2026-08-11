package com.darkedges.oid4vci.demo.issuer;

import java.time.Instant;
import java.util.Optional;

/**
 * One identity-proofing round trip: created when a Wallet asks to be proofed, completed when the
 * proofing service reports a passing result, and read once by the Wallet to collect its offer.
 *
 * <p><strong>Deliberately holds no passport data.</strong> When a result arrives, the claims go
 * straight into the {@code PreAuthorizedCodeSession} keyed by the pre-authorized code, and this
 * session keeps only that code. So the PII lives in exactly one place, behind a single-use code,
 * instead of being copied into a second store with its own lifetime and its own eviction bug waiting
 * to happen.
 *
 * <p>The code rather than a built Credential Offer, and the difference is not cosmetic. An offer
 * carries {@code credential_issuer}, and this issuer derives its own address from the address the
 * caller used (see {@code RequestBaseUrl}) because one deployment is reachable at several. Building
 * the offer when the <em>proofing service</em> reports a result would stamp it with whatever address
 * that service used — an in-cluster name, a Docker alias — and hand the Wallet an issuer it cannot
 * reach. Keeping the code means the offer is built when the Wallet collects it, addressed as the
 * Wallet itself arrived.
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
        Optional<String> preAuthorizedCode,
        Optional<String> credentialConfigurationId,
        Optional<String> failureReason,
        Instant expiresAt) {

    public enum Status {
        /** Created; the user is somewhere in the proofing app, or has abandoned it. */
        PENDING,
        /** Proofing passed and a code is waiting to be collected as an offer. */
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
        preAuthorizedCode = preAuthorizedCode == null ? Optional.empty() : preAuthorizedCode;
        credentialConfigurationId =
                credentialConfigurationId == null ? Optional.empty() : credentialConfigurationId;
        failureReason = failureReason == null ? Optional.empty() : failureReason;
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
        if (status == Status.READY && (preAuthorizedCode.isEmpty() || credentialConfigurationId.isEmpty())) {
            throw new IllegalArgumentException(
                    "a READY session must carry a pre-authorized code and a configuration id");
        }
    }

    public static ProofingSession pending(String id, String retrievalSecret, Instant expiresAt) {
        return new ProofingSession(
                id, retrievalSecret, Status.PENDING, Optional.empty(), Optional.empty(), Optional.empty(), expiresAt);
    }

    public ProofingSession ready(String preAuthorizedCode, String credentialConfigurationId) {
        return new ProofingSession(
                id, retrievalSecret, Status.READY, Optional.of(preAuthorizedCode),
                Optional.of(credentialConfigurationId), Optional.empty(), expiresAt);
    }

    public ProofingSession failed(String reason) {
        return new ProofingSession(
                id, retrievalSecret, Status.FAILED, Optional.empty(), Optional.empty(),
                Optional.of(reason), expiresAt);
    }

    public boolean isExpired(Instant now) {
        return expiresAt.isBefore(now);
    }
}
