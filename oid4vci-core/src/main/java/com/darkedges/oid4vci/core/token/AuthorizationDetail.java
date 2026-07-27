package com.darkedges.oid4vci.core.token;

import java.util.List;
import java.util.Optional;

/**
 * One entry of a Token Response's {@code authorization_details} array (OID4VCI 1.0, Section 6.2 — RFC
 * 9396 Rich Authorization Requests, {@code type: "openid_credential"}).
 *
 * @param credentialConfigurationId REQUIRED — which configuration this authorization detail grants
 *                                  access to.
 * @param credentialIdentifiers    OPTIONAL — present when the Credential Issuer pre-allocated specific
 *                                 instance identifiers (e.g. one per distinct claim set behind the same
 *                                 pre-authorized code); a Credential Request then references one of these
 *                                 via {@code credential_identifier} instead of
 *                                 {@code credential_configuration_id}.
 */
public record AuthorizationDetail(String credentialConfigurationId, Optional<List<String>> credentialIdentifiers) {

    /** The fixed RFC 9396 {@code type} discriminant for an OID4VCI authorization detail — always this
     * value, never modeled as a variable field. */
    public static final String TYPE = "openid_credential";

    public AuthorizationDetail {
        if (credentialConfigurationId == null || credentialConfigurationId.isBlank()) {
            throw new IllegalArgumentException("credential_configuration_id is required");
        }
        credentialIdentifiers = credentialIdentifiers == null
                ? Optional.empty()
                : credentialIdentifiers.map(List::copyOf);
    }
}
