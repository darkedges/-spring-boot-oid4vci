package com.darkedges.oid4vci.demo.issuer;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code demo.proofing.*} configuration, following the {@code client-attestation-trusted-issuer}
 * precedent in {@code application.yml}: a property pair rather than key material in code.
 *
 * <p>{@link #callbackSecret} has no default, and that is the point. A default would be a published
 * credential — anyone who could reach the host could post a result asserting any identity and be
 * handed a credential for it. The result endpoint refuses every request while the secret is unset,
 * so a misconfigured deployment fails closed instead of running wide open.
 */
@ConfigurationProperties(prefix = "demo.proofing")
public class ProofingProperties {

    /**
     * Shared secret the identity-proofing service presents on {@code POST /proofing/result}.
     *
     * <p>Set it from the environment, never in a checked-in file. A real deployment would use mTLS or
     * a signed assertion; a shared secret is the demo-scale version of the same requirement, and the
     * requirement itself is not optional.
     */
    private String callbackSecret;

    /** How long a proofing session stays collectable. Long enough to read a passport, short enough
     * that an abandoned one does not linger. */
    private Duration sessionTtl = Duration.ofMinutes(15);

    /** How long the minted pre-authorized code lives once proofing succeeds. Matches the demo offer
     * endpoint's own ten minutes. */
    private Duration preAuthorizedCodeTtl = Duration.ofMinutes(10);

    /** Which credential configuration a passing proofing result is issued as. */
    private String credentialConfigurationId = "PassportCredential";

    public String getCallbackSecret() {
        return callbackSecret;
    }

    public void setCallbackSecret(String callbackSecret) {
        this.callbackSecret = callbackSecret;
    }

    public Duration getSessionTtl() {
        return sessionTtl;
    }

    public void setSessionTtl(Duration sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    public Duration getPreAuthorizedCodeTtl() {
        return preAuthorizedCodeTtl;
    }

    public void setPreAuthorizedCodeTtl(Duration preAuthorizedCodeTtl) {
        this.preAuthorizedCodeTtl = preAuthorizedCodeTtl;
    }

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {
        this.credentialConfigurationId = credentialConfigurationId;
    }
}
