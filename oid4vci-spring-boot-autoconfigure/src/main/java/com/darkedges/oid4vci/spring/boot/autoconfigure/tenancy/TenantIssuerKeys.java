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

    public TenantIssuerKeys(TenantRepository tenants, TenantKeyService keys) {
        if (!keys.purposes().contains(SIGNING)) {
            throw new IllegalStateException("oid4vc.tenancy.keys.purposes must include \"" + SIGNING + "\" for an issuer");
        }
        this.tenants = tenants;
        this.keys = keys;
    }

    @Override
    public ECKey signingKey(IssuerContext context) {
        return keys.activeKey(tenant(context), SIGNING).key();
    }

    @Override
    public List<ECKey> verificationKeys(IssuerContext context) {
        Tenant tenant = tenant(context);
        List<TenantKey> published = keys.publishedKeys(tenant, SIGNING);
        if (published.isEmpty()) published = List.of(keys.activeKey(tenant, SIGNING));
        return published.stream().map(TenantKey::publicJwk).toList();
    }

    @Override
    public Optional<MdocSigningKey> mdocKey(IssuerContext context) {
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
