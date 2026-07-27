package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.offer.CredentialOffer;

import java.util.Optional;

/**
 * Where a Credential Offer transported by reference ({@code credential_offer_uri}) lives between being
 * minted and being fetched by the Wallet. Minting an offer (choosing which
 * {@code credential_configuration_ids} and pre-authorized code to include) is deployment-specific issuer
 * business logic — deliberately not exposed as a public endpoint here, mirroring how oid4vp keeps trust
 * decisions like {@code IssuerKeyResolver} out of its autoconfigured surface; only fetching an
 * already-minted offer by id is a public {@code oid4vci-issuer-web} endpoint.
 */
public interface CredentialOfferStore {

    void save(String offerId, CredentialOffer offer);

    /** Not single-use, unlike {@link PreAuthorizedCodeStore}/{@link NonceStore} — a Wallet may
     * legitimately re-fetch the same {@code credential_offer_uri} (e.g. after a dropped connection)
     * before ever attempting to redeem the pre-authorized code it references. */
    Optional<CredentialOffer> find(String offerId);
}
