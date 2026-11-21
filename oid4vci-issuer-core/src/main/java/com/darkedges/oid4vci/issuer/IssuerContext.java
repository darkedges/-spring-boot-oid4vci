package com.darkedges.oid4vci.issuer;

import java.util.Objects;

/**
 * Which issuer a request is for: the tenant, and the Credential Issuer Identifier it was reached on.
 *
 * <p>A single-tenant deployment has one tenant, {@link #DEFAULT_TENANT}, whose identifier is the URL the request arrived on. A
 * multi-tenant deployment resolves both from the request (see {@code oid4vc-tenancy}).
 *
 * <p>Everything an issuer keeps between requests (codes, nonces, offers, the claims behind an access token) is kept under a
 * {@linkplain #scope(String) scoped key}, so what one tenant issued can never be redeemed at another.
 *
 * @param tenantId         the tenant; {@link #DEFAULT_TENANT} for a single-tenant deployment
 * @param issuerIdentifier the Credential Issuer Identifier, such as {@code https://issuer.zkp.au/t/bank}, without a trailing slash
 */
public record IssuerContext(String tenantId, String issuerIdentifier) {

    public static final String DEFAULT_TENANT = "default";

    /** Separates the tenant from the key in a scoped key. Never part of a key the issuer generates. */
    static final char SEPARATOR = '|';

    public IssuerContext {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(issuerIdentifier, "issuerIdentifier");
        if (tenantId.isEmpty() || tenantId.indexOf(SEPARATOR) >= 0) throw new IllegalArgumentException("bad tenant id: " + tenantId);
        if (issuerIdentifier.endsWith("/")) issuerIdentifier = issuerIdentifier.substring(0, issuerIdentifier.length() - 1);
    }

    /** The single tenant of a single-tenant deployment, reached on {@code issuerIdentifier}. */
    public static IssuerContext single(String issuerIdentifier) {
        return new IssuerContext(DEFAULT_TENANT, issuerIdentifier);
    }

    public boolean isDefaultTenant() {
        return DEFAULT_TENANT.equals(tenantId);
    }

    /**
     * The key under which this tenant keeps {@code key}: {@code <tenant>|<key>}, or {@code key} itself for the default tenant, so a
     * single-tenant deployment's stored entries (and code that stores them directly) are unchanged.
     *
     * <p>A key that contains the separator is refused: otherwise a request at the default tenant could name another tenant's entry.
     *
     * @throws IllegalArgumentException for a missing key, or one containing {@code |}
     */
    public String scope(String key) {
        if (key == null || key.isEmpty() || key.indexOf(SEPARATOR) >= 0) {
            throw new IllegalArgumentException("not a key this issuer could have issued");
        }
        return isDefaultTenant() ? key : tenantId + SEPARATOR + key;
    }

    /** {@link #scope}, or empty for a key this issuer could not have issued. */
    public java.util.Optional<String> scopeIfValid(String key) {
        try {
            return java.util.Optional.of(scope(key));
        } catch (IllegalArgumentException e) {
            return java.util.Optional.empty();
        }
    }

    /** An endpoint of this issuer, such as {@code /token}. */
    public String url(String path) {
        return issuerIdentifier + (path.startsWith("/") ? path : "/" + path);
    }
}
