package com.darkedges.oid4vci.issuer;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What a pre-authorized code, once redeemed, authorizes: which credential configurations the resulting
 * access token may be used for, the expected {@code tx_code} (if the offer required one), and the actual
 * claim values to issue — e.g. {@code given_name=Jane} — set by whatever created the offer (the demo
 * Issuer app's seeding endpoint in this project; a real issuer's own enrollment/KYC process elsewhere).
 *
 * <p>{@code claims} is a flat map regardless of credential format: {@link SdJwtVcCredentialIssuanceService}
 * uses it directly as top-level claims, while {@link MsoMdocCredentialIssuanceService} groups it into
 * mdoc namespaces using the target {@code CredentialConfiguration}'s own declared claim paths.
 */
public record PreAuthorizedCodeSession(
        List<String> credentialConfigurationIds, Optional<String> expectedTxCode, Map<String, String> claims, Instant expiresAt) {

    public PreAuthorizedCodeSession {
        if (credentialConfigurationIds == null || credentialConfigurationIds.isEmpty()) {
            throw new IllegalArgumentException("credentialConfigurationIds must be non-empty");
        }
        credentialConfigurationIds = List.copyOf(credentialConfigurationIds);
        expectedTxCode = expectedTxCode == null ? Optional.empty() : expectedTxCode;
        claims = claims == null ? Map.of() : Map.copyOf(claims);
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
    }
}
