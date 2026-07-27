package com.darkedges.oid4vci.core.offer;

import java.net.URI;
import java.util.Optional;

/**
 * The {@code urn:ietf:params:oauth:grant-type:pre-authorized_code} entry of a Credential Offer's
 * {@code grants} object (OID4VCI 1.0, Section 4.1.1).
 *
 * @param preAuthorizedCode REQUIRED — the code the Wallet redeems at the Token Endpoint.
 * @param txCode            OPTIONAL — present iff the Credential Issuer also requires a transaction code.
 * @param authorizationServer OPTIONAL — which of the Credential Issuer's advertised Authorization
 *                            Servers this code was issued by, if more than one is configured.
 */
public record PreAuthorizedCodeGrant(
        String preAuthorizedCode, Optional<TxCode> txCode, Optional<URI> authorizationServer) {

    public PreAuthorizedCodeGrant {
        if (preAuthorizedCode == null || preAuthorizedCode.isBlank()) {
            throw new IllegalArgumentException("pre-authorized_code is required");
        }
        txCode = txCode == null ? Optional.empty() : txCode;
        authorizationServer = authorizationServer == null ? Optional.empty() : authorizationServer;
    }
}
