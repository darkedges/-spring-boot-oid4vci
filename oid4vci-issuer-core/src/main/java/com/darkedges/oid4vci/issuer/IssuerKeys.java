package com.darkedges.oid4vci.issuer;

import com.nimbusds.jose.jwk.ECKey;

import java.security.PrivateKey;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The keys an issuer signs with, per tenant: access tokens and SD-JWT VCs with the {@linkplain #signingKey signing key}, mdocs with
 * the {@linkplain #mdocKey mdoc key}. A single-tenant deployment has one of each ({@link #fixed}); a multi-tenant one looks them up
 * per tenant.
 */
public interface IssuerKeys {

    /** The tenant's active signing key, with its private part (and its {@code x5c} certificate chain, if it has one). */
    ECKey signingKey(IssuerContext context);

    /** The tenant's published public keys: the active one, and retired ones whose tokens and credentials may still be presented. */
    List<ECKey> verificationKeys(IssuerContext context);

    /** The tenant's mdoc signing key, if it issues mdocs. */
    default Optional<MdocSigningKey> mdocKey(IssuerContext context) {
        return Optional.empty();
    }

    /**
     * An mdoc issuer key.
     *
     * @param certificateChain base64 DER certificates, the key's own first (the MSO's {@code x5chain})
     */
    record MdocSigningKey(PrivateKey privateKey, List<String> certificateChain) {
        public MdocSigningKey {
            Objects.requireNonNull(privateKey, "privateKey");
            certificateChain = certificateChain == null ? List.of() : List.copyOf(certificateChain);
        }
    }

    /** The same keys for every request: a single-tenant deployment. Either may be {@code null}, for a deployment issuing only mdocs or only SD-JWT VCs. */
    static IssuerKeys fixed(ECKey signingKey, MdocSigningKey mdoc) {
        List<ECKey> published = signingKey == null ? List.of() : List.of(signingKey.toPublicJWK());
        return new IssuerKeys() {
            @Override
            public ECKey signingKey(IssuerContext context) {
                if (signingKey == null) throw new IllegalStateException("this issuer has no signing key");
                return signingKey;
            }

            @Override
            public List<ECKey> verificationKeys(IssuerContext context) {
                return published;
            }

            @Override
            public Optional<MdocSigningKey> mdocKey(IssuerContext context) {
                return Optional.ofNullable(mdoc);
            }
        };
    }
}
