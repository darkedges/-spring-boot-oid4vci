package com.darkedges.oid4vci.core.token;

/** A Nonce Endpoint response (OID4VCI 1.0, Section 7.2) — {@code {"c_nonce": "..."}}, served with
 * {@code Cache-Control: no-store} (a transport-layer concern for the web module, not this model). */
public record NonceResponse(String cNonce) {

    public NonceResponse {
        if (cNonce == null || cNonce.isBlank()) {
            throw new IllegalArgumentException("c_nonce is required");
        }
    }
}
