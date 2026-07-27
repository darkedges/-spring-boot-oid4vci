package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.offer.CredentialOffer;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Default in-memory {@link CredentialOfferStore} — see {@link InMemoryPreAuthorizedCodeStore}'s
 * Javadoc for why this lives here rather than in a separate autoconfiguration-only module. */
public final class InMemoryCredentialOfferStore implements CredentialOfferStore {

    private final Map<String, CredentialOffer> offers = new ConcurrentHashMap<>();

    @Override
    public void save(String offerId, CredentialOffer offer) {
        offers.put(offerId, offer);
    }

    @Override
    public Optional<CredentialOffer> find(String offerId) {
        return Optional.ofNullable(offers.get(offerId));
    }
}
