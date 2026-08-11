package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciException;

/**
 * Issues and consumes single-use attestation Challenges (draft-ietf-oauth-attestation-based-client-auth
 * Section 6) for {@link ClientAttestationValidator} — the same single-use-token machinery
 * {@link NonceService} already provides for OID4VCI's {@code c_nonce}, wrapped in a distinctly-typed
 * class rather than exposed as a second {@code NonceService} bean: this feature is optional and often
 * disabled, and a second bean of the exact same type would leave Spring unable to tell "the challenge
 * feature isn't configured" apart from "there's only the unrelated {@code c_nonce} service to wire in" —
 * a dedicated type makes that {@code Optional.empty()} unambiguous.
 */
public final class AttestationChallengeService {

    private final NonceService delegate;

    public AttestationChallengeService(NonceService delegate) {
        this.delegate = delegate;
    }

    public String issue() {
        return delegate.issue();
    }

    /** @return {@code true} if {@code challenge} was a valid, unconsumed, unexpired Challenge (and has
     * now been consumed); {@code false} otherwise — deliberately non-throwing, unlike
     * {@link NonceService#requireValid}, so the caller can throw its own
     * {@code AttestationChallengeRequiredException} carrying a fresh replacement Challenge. */
    public boolean tryConsume(String challenge) {
        try {
            delegate.requireValid(challenge);
            return true;
        } catch (Oid4vciException e) {
            return false;
        }
    }
}
