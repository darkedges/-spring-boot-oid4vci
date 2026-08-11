package com.darkedges.oid4vci.spring.boot.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code oid4vci.issuer.*} configuration properties, shaped after oid4vp's own {@code Oid4vpProperties}.
 *
 * <p>{@code credential-configurations-supported} is bound as a single raw JSON object (the whole map, not
 * one property per entry) rather than nested YAML/properties keys — same justification as
 * {@code dcql-query}/{@code client-metadata} in oid4vp: {@link com.darkedges.oid4vci.core.metadata.CredentialConfiguration}'s
 * sealed-interface/{@code Optional}-heavy shape doesn't map onto Spring Boot's relaxed property binder,
 * and it's naturally already one logical JSON map rather than several independent scalar fields.
 */
@ConfigurationProperties(prefix = "oid4vci.issuer")
public class Oid4vciIssuerProperties {

    /** Appended to the resolved base URL (see {@code RequestBaseUrl}, {@code oid4vci-issuer-web}) for the
     * {@code credential_endpoint} metadata field. There's no {@code credential-issuer} property: the
     * Issuer's own base URL is derived from each request's scheme/host, not fixed config -- the same
     * deployment may be reachable at more than one address (an internal Docker network alias, a public
     * reverse-proxy hostname, ...), and whichever one a client actually used is what must come back. */
    private String credentialEndpointPath = "/credential";

    /** Appended to the resolved base URL for the {@code nonce_endpoint} metadata field. */
    private String nonceEndpointPath = "/nonce";

    /** The {@code credential_configurations_supported} map, as one JSON object. */
    private String credentialConfigurationsSupported;

    /** Advertises {@code batch_credential_issuance.batch_size} in the Issuer Metadata (OID4VCI 1.0 Final
     * Section 12.2.4) and allows the Credential Endpoint to accept up to this many proofs in a single
     * Credential Request, one Credential minted per proof. {@code null} (the default) means batch
     * issuance isn't advertised and the Credential Endpoint accepts at most one proof per request. Must
     * be 2 or greater when set — see {@code BatchCredentialIssuance}. */
    private Integer batchCredentialIssuanceMaxSize;

    private Duration accessTokenTtl = Duration.ofMinutes(5);

    private Duration nonceTtl = Duration.ofMinutes(5);

    private Duration proofClockSkew = Duration.ofMinutes(5);

    private Duration credentialValidity = Duration.ofDays(365);

    /** How fresh a DPoP proof's {@code iat} must be (RFC 9449) — tighter than {@link #proofClockSkew}
     * since, with no server-provided DPoP nonce implemented, this window is the main replay defense
     * alongside the single-use {@code jti} check. */
    private Duration dpopProofFreshness = Duration.ofMinutes(1);

    /** How fresh a Client Attestation PoP JWT's {@code iat} must be (see
     * {@code ClientAttestationValidator}) — same replay-defense role {@link #dpopProofFreshness} plays
     * for DPoP proofs, just for {@code attest_jwt_client_auth} instead. Only relevant once a
     * {@code ClientAttestationTrustAnchor} is configured (see below, or supplied directly as a bean). */
    private Duration attestationPopFreshness = Duration.ofMinutes(1);

    /** The Wallet Provider {@code iss} identifier this issuer trusts to vouch for a Wallet instance via a
     * Client Attestation JWT (see {@code ClientAttestationTrustAnchor}). Both this and
     * {@link #clientAttestationTrustedIssuerKey} must be set together to enable
     * {@code attest_jwt_client_auth} — plain config properties rather than requiring a hand-written
     * {@code @Bean}, so a consuming app can turn this on without any Java code; a consuming app that needs
     * something more dynamic (e.g. resolving trust from multiple Wallet Providers) can still supply its
     * own {@code ClientAttestationTrustAnchor} bean directly instead, which backs this off. */
    private String clientAttestationTrustedIssuer;

    /** Public JWK (JSON, must include an explicit {@code alg}) of the trusted Wallet Provider's signing
     * key — see {@link #clientAttestationTrustedIssuer}. */
    private String clientAttestationTrustedIssuerKey;

    /** Enables the Challenge Endpoint (draft-ietf-oauth-attestation-based-client-auth Section 6) at this
     * path, and requires a matching, single-use {@code challenge} claim on every Client Attestation PoP
     * JWT. {@code null} (the default) leaves the feature off entirely — it's spec-optional ({@code MAY}),
     * and turning it on unconditionally would break every existing {@code attest_jwt_client_auth} Wallet
     * integration that doesn't yet call it. */
    private String attestationChallengeEndpointPath;

    public String getCredentialEndpointPath() {
        return credentialEndpointPath;
    }

    public void setCredentialEndpointPath(String credentialEndpointPath) {
        this.credentialEndpointPath = credentialEndpointPath;
    }

    public String getNonceEndpointPath() {
        return nonceEndpointPath;
    }

    public void setNonceEndpointPath(String nonceEndpointPath) {
        this.nonceEndpointPath = nonceEndpointPath;
    }

    public String getCredentialConfigurationsSupported() {
        return credentialConfigurationsSupported;
    }

    public void setCredentialConfigurationsSupported(String credentialConfigurationsSupported) {
        this.credentialConfigurationsSupported = credentialConfigurationsSupported;
    }

    public Integer getBatchCredentialIssuanceMaxSize() {
        return batchCredentialIssuanceMaxSize;
    }

    public void setBatchCredentialIssuanceMaxSize(Integer batchCredentialIssuanceMaxSize) {
        this.batchCredentialIssuanceMaxSize = batchCredentialIssuanceMaxSize;
    }

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public Duration getNonceTtl() {
        return nonceTtl;
    }

    public void setNonceTtl(Duration nonceTtl) {
        this.nonceTtl = nonceTtl;
    }

    public Duration getProofClockSkew() {
        return proofClockSkew;
    }

    public void setProofClockSkew(Duration proofClockSkew) {
        this.proofClockSkew = proofClockSkew;
    }

    public Duration getCredentialValidity() {
        return credentialValidity;
    }

    public void setCredentialValidity(Duration credentialValidity) {
        this.credentialValidity = credentialValidity;
    }

    public Duration getDpopProofFreshness() {
        return dpopProofFreshness;
    }

    public void setDpopProofFreshness(Duration dpopProofFreshness) {
        this.dpopProofFreshness = dpopProofFreshness;
    }

    public Duration getAttestationPopFreshness() {
        return attestationPopFreshness;
    }

    public void setAttestationPopFreshness(Duration attestationPopFreshness) {
        this.attestationPopFreshness = attestationPopFreshness;
    }

    public String getClientAttestationTrustedIssuer() {
        return clientAttestationTrustedIssuer;
    }

    public void setClientAttestationTrustedIssuer(String clientAttestationTrustedIssuer) {
        this.clientAttestationTrustedIssuer = clientAttestationTrustedIssuer;
    }

    public String getClientAttestationTrustedIssuerKey() {
        return clientAttestationTrustedIssuerKey;
    }

    public void setClientAttestationTrustedIssuerKey(String clientAttestationTrustedIssuerKey) {
        this.clientAttestationTrustedIssuerKey = clientAttestationTrustedIssuerKey;
    }

    public String getAttestationChallengeEndpointPath() {
        return attestationChallengeEndpointPath;
    }

    public void setAttestationChallengeEndpointPath(String attestationChallengeEndpointPath) {
        this.attestationChallengeEndpointPath = attestationChallengeEndpointPath;
    }
}
