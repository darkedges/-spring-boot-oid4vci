package com.darkedges.oid4vci.issuer;

import java.util.Objects;
import java.util.Optional;

/** The Wallet Provider each tenant trusts for {@code attest_jwt_client_auth}; none means the tenant doesn't accept it. */
@FunctionalInterface
public interface ClientAttestationTrustAnchors {

    Optional<ClientAttestationTrustAnchor> forContext(IssuerContext context);

    /** The same Wallet Provider for every request: a single-tenant deployment. */
    static ClientAttestationTrustAnchors fixed(ClientAttestationTrustAnchor anchor) {
        Objects.requireNonNull(anchor, "anchor");
        Optional<ClientAttestationTrustAnchor> found = Optional.of(anchor);
        return context -> found;
    }
}
