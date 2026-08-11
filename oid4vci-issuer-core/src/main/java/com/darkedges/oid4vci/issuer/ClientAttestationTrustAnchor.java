package com.darkedges.oid4vci.issuer;

import com.nimbusds.jose.jwk.ECKey;

/**
 * The Wallet Provider this issuer trusts to vouch for a Wallet instance's key via a Client Attestation JWT
 * (see {@link ClientAttestationValidator}). {@code trustedIssuer} must match that JWT's {@code iss} claim;
 * {@code trustedIssuerKey} verifies its signature. Supplying this bean is what opts an issuer into
 * accepting {@code attest_jwt_client_auth} at the Token Endpoint at all — omitting it leaves that
 * authentication method unadvertised and unsupported, the same "absence leaves the slice unwired" pattern
 * {@code MdocIssuerKeyMaterial} already uses.
 */
public record ClientAttestationTrustAnchor(String trustedIssuer, ECKey trustedIssuerKey) {

    public ClientAttestationTrustAnchor {
        if (trustedIssuer == null || trustedIssuer.isBlank()) {
            throw new IllegalArgumentException("trustedIssuer is required");
        }
        if (trustedIssuerKey == null) {
            throw new IllegalArgumentException("trustedIssuerKey is required");
        }
    }
}
