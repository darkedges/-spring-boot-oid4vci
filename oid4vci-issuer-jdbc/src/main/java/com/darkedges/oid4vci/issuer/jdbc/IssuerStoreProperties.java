package com.darkedges.oid4vci.issuer.jdbc;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** {@code oid4vci.issuer.store.*}: where the issuer keeps codes, nonces, offers and the claims behind access tokens. */
@ConfigurationProperties(prefix = "oid4vci.issuer.store")
public class IssuerStoreProperties {

    /** {@code jdbc} for PostgreSQL (the application's DataSource); otherwise the stores are in memory. */
    private String type = "memory";

    /**
     * Base64 of 32 random bytes ({@code ISSUER_STORE_ENCRYPTION_KEY}), required for {@code jdbc}: entries hold identity claims, and
     * are encrypted with it. Losing it loses only entries in flight (codes, offers, live tokens' claims).
     */
    private String encryptionKey;

    /** Creates the table at start-up if it doesn't exist. */
    private boolean initializeSchema = true;

    /** How long a Credential Offer by reference is kept (an offer has no expiry of its own). */
    private Duration offerTtl = Duration.ofHours(24);

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
    public boolean isInitializeSchema() { return initializeSchema; }
    public void setInitializeSchema(boolean initializeSchema) { this.initializeSchema = initializeSchema; }
    public Duration getOfferTtl() { return offerTtl; }
    public void setOfferTtl(Duration offerTtl) { this.offerTtl = offerTtl; }
}
