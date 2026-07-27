package com.darkedges.oid4vci.core.offer;

import java.util.Optional;

/** A Credential Offer's {@code grants} object (OID4VCI 1.0, Section 4.1.1) — at least one of the two
 * entries must be present when {@code grants} itself is present. */
public record Grants(Optional<AuthorizationCodeGrant> authorizationCode, Optional<PreAuthorizedCodeGrant> preAuthorizedCode) {

    public Grants {
        authorizationCode = authorizationCode == null ? Optional.empty() : authorizationCode;
        preAuthorizedCode = preAuthorizedCode == null ? Optional.empty() : preAuthorizedCode;
        if (authorizationCode.isEmpty() && preAuthorizedCode.isEmpty()) {
            throw new IllegalArgumentException("grants must contain at least one grant type");
        }
    }
}
