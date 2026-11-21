package com.darkedges.oid4vci.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.keys.TenantKey;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;

import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Each tenant's own issuer keys, from {@link TenantKeyService}: {@value #SIGNING} signs its access tokens and SD-JWT VCs,
 * {@value #MDOC} its mdocs. Each is created the first time the tenant needs it, with a certificate from the deployment's CA.
 */
public final class TenantIssuerKeys implements IssuerKeys {

    public static final String SIGNING = "issuer-signing";
    public static final String MDOC = "mdoc";

    private final TenantRepository tenants;
    private final TenantKeyService keys;
    /** The deployment's default tenant, which keeps signing with the application's own keys; {@code null} if none. */
    private final String applicationKeysTenant;
    private final IssuerKeys applicationKeys;

    public TenantIssuerKeys(TenantRepository tenants, TenantKeyService keys) {
        this(tenants, keys, null, null);
    }

    /**
     * @param applicationKeysTenant a tenant (the deployment's default tenant) that keeps the application's own keys, so the
     *                              issuer that was single-tenant keeps the keys wallets and verifiers already trust
     * @param applicationKeys       those keys: its mdoc key, if absent, is the tenant's own
     */
    public TenantIssuerKeys(TenantRepository tenants, TenantKeyService keys, String applicationKeysTenant, IssuerKeys applicationKeys) {
        if (!keys.purposes().contains(SIGNING)) {
            throw new IllegalStateException("oid4vc.tenancy.keys.purposes must include \"" + SIGNING + "\" for an issuer");
        }
        this.tenants = tenants;
        this.keys = keys;
        this.applicationKeysTenant = applicationKeys == null ? null : applicationKeysTenant;
        this.applicationKeys = applicationKeys;
    }

    private boolean usesApplicationKeys(IssuerContext context) {
        return applicationKeysTenant != null && applicationKeysTenant.equals(context.tenantId());
    }

    @Override
    public ECKey signingKey(IssuerContext context) {
        if (usesApplicationKeys(context)) return applicationKeys.signingKey(context);
        return keys.activeKey(tenant(context), SIGNING).key();
    }

    @Override
    public List<ECKey> verificationKeys(IssuerContext context) {
        if (usesApplicationKeys(context)) return applicationKeys.verificationKeys(context);
        Tenant tenant = tenant(context);
        List<TenantKey> published = keys.publishedKeys(tenant, SIGNING);
        if (published.isEmpty()) published = List.of(keys.activeKey(tenant, SIGNING));
        return published.stream().map(TenantKey::publicJwk).toList();
    }

    @Override
    public Optional<MdocSigningKey> mdocKey(IssuerContext context) {
        if (usesApplicationKeys(context)) {
            Optional<MdocSigningKey> own = applicationKeys.mdocKey(context);
            if (own.isPresent()) return own;
        }
        if (!keys.purposes().contains(MDOC)) return Optional.empty();
        TenantKey key = keys.activeKey(tenant(context), MDOC);
        try {
            return Optional.of(new MdocSigningKey(key.key().toECPrivateKey(),
                    List.of(Base64.getEncoder().encodeToString(key.certificate().getEncoded()))));
        } catch (JOSEException | CertificateEncodingException e) {
            throw new IllegalStateException("unusable mdoc key for tenant " + context.tenantId(), e);
        }
    }

    private Tenant tenant(IssuerContext context) {
        return tenants.findById(context.tenantId())
                .orElseThrow(() -> new IllegalStateException("no tenant " + context.tenantId()));
    }
}
