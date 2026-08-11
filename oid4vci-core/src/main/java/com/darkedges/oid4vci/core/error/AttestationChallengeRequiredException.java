package com.darkedges.oid4vci.core.error;

/**
 * Thrown when a Client Attestation PoP JWT is missing, or presents an invalid/expired/already-used,
 * {@code challenge} claim, and this Authorization Server's Challenge Endpoint
 * (draft-ietf-oauth-attestation-based-client-auth Section 6) is configured to require one. Carries a
 * freshly issued challenge so {@code Oid4vciExceptionHandler} can return it via the
 * {@code OAuth-Client-Attestation-Challenge} response header (Section 6.2), letting the Wallet retry
 * immediately with a corrected PoP JWT — the same reactive-nonce shape {@code invalid_proof}/
 * {@code c_nonce} already uses for Credential Requests.
 */
public final class AttestationChallengeRequiredException extends Oid4vciException {

    private final String challenge;

    public AttestationChallengeRequiredException(String challenge, String message) {
        super(Oid4vciErrorCode.USE_ATTESTATION_CHALLENGE, message);
        if (challenge == null || challenge.isBlank()) {
            throw new IllegalArgumentException("challenge is required");
        }
        this.challenge = challenge;
    }

    public String challenge() {
        return challenge;
    }
}
