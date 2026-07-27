package com.darkedges.oid4vci.core.offer;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * A Credential Offer (OID4VCI 1.0, Section 4.1.1) — either transported by value (the
 * {@code credential_offer} query parameter) or by reference ({@code credential_offer_uri}, fetched by
 * the Wallet as a separate {@code GET}); this type represents the resolved object either way.
 *
 * @param credentialIssuer         REQUIRED — the Credential Issuer's identifier.
 * @param credentialConfigurationIds REQUIRED non-empty — keys into the Credential Issuer's
 *                                  {@code credential_configurations_supported} map.
 * @param grants                   OPTIONAL — if absent, the Wallet is expected to already know (or
 *                                  determine out of band) which grant type to use.
 */
public record CredentialOffer(URI credentialIssuer, List<String> credentialConfigurationIds, Optional<Grants> grants) {

    public CredentialOffer {
        if (credentialIssuer == null) {
            throw new IllegalArgumentException("credential_issuer is required");
        }
        if (credentialConfigurationIds == null || credentialConfigurationIds.isEmpty()) {
            throw new IllegalArgumentException("credential_configuration_ids must be a non-empty array");
        }
        credentialConfigurationIds = List.copyOf(credentialConfigurationIds);
        grants = grants == null ? Optional.empty() : grants;
    }
}
