package com.darkedges.oid4vci.core.credential;

import java.util.Optional;

/**
 * A Credential Request (OID4VCI 1.0, Section 8.2), sent to the Credential Endpoint with a bearer access
 * token. Exactly one of {@code credentialConfigurationId}/{@code credentialIdentifier} is present: the
 * former for the simple case (the access token wasn't scoped to specific pre-allocated identifiers via
 * {@code authorization_details.credential_identifiers}); the latter otherwise — confirmed against the
 * spec's own Section 8.2 worked example, which uses {@code credential_identifier}.
 */
public record CredentialRequest(
        Optional<String> credentialConfigurationId, Optional<String> credentialIdentifier, Optional<Proofs> proofs) {

    public CredentialRequest {
        credentialConfigurationId = credentialConfigurationId == null ? Optional.empty() : credentialConfigurationId;
        credentialIdentifier = credentialIdentifier == null ? Optional.empty() : credentialIdentifier;
        proofs = proofs == null ? Optional.empty() : proofs;
        if (credentialConfigurationId.isEmpty() && credentialIdentifier.isEmpty()) {
            throw new IllegalArgumentException(
                    "exactly one of credential_configuration_id/credential_identifier is required");
        }
        if (credentialConfigurationId.isPresent() && credentialIdentifier.isPresent()) {
            throw new IllegalArgumentException(
                    "credential_configuration_id and credential_identifier are mutually exclusive");
        }
    }
}
