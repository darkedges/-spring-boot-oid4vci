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

    /** The Credential Issuer's own identifier/base URL, e.g. {@code https://issuer.example.org}. */
    private String credentialIssuer;

    /** Appended to {@link #credentialIssuer} for the {@code credential_endpoint} metadata field. */
    private String credentialEndpointPath = "/credential";

    /** Appended to {@link #credentialIssuer} for the {@code nonce_endpoint} metadata field. */
    private String nonceEndpointPath = "/nonce";

    /** The {@code credential_configurations_supported} map, as one JSON object. */
    private String credentialConfigurationsSupported;

    private Duration accessTokenTtl = Duration.ofMinutes(5);

    private Duration nonceTtl = Duration.ofMinutes(5);

    private Duration proofClockSkew = Duration.ofMinutes(5);

    private Duration credentialValidity = Duration.ofDays(365);

    public String getCredentialIssuer() {
        return credentialIssuer;
    }

    public void setCredentialIssuer(String credentialIssuer) {
        this.credentialIssuer = credentialIssuer;
    }

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
}
