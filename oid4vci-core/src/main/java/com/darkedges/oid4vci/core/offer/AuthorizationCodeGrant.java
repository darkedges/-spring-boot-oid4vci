package com.darkedges.oid4vci.core.offer;

import java.net.URI;
import java.util.Optional;

/**
 * The {@code authorization_code} entry of a Credential Offer's {@code grants} object (OID4VCI 1.0,
 * Section 4.1.1). Modeled so a Credential Offer using this grant still parses and round-trips
 * correctly, but no v1 code path actually drives the interactive Authorization Code Grant flow this
 * describes — see the project README's "v1 scope" note.
 *
 * @param issuerState        OPTIONAL — a string the Credential Issuer can use to bind this offer to a
 *                            later Authorization Request.
 * @param authorizationServer OPTIONAL — same purpose as {@link PreAuthorizedCodeGrant#authorizationServer}.
 */
public record AuthorizationCodeGrant(Optional<String> issuerState, Optional<URI> authorizationServer) {

    public AuthorizationCodeGrant {
        issuerState = issuerState == null ? Optional.empty() : issuerState;
        authorizationServer = authorizationServer == null ? Optional.empty() : authorizationServer;
    }
}
