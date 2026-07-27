package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferWriter;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Serves a Credential Offer transported by reference ({@code credential_offer_uri}). Minting an offer
 * (choosing configurations/pre-authorized code) is deployment-specific business logic, deliberately not
 * exposed as a public endpoint here — see {@link CredentialOfferStore}'s Javadoc.
 *
 * <p>Returns a pre-serialized {@code String} — see {@link IssuerMetadataController}'s Javadoc for why.
 */
@RestController
public class CredentialOfferController {

    private final CredentialOfferStore store;

    public CredentialOfferController(CredentialOfferStore store) {
        this.store = store;
    }

    @GetMapping(value = "/credential-offer/{offerId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> offer(@PathVariable String offerId) {
        CredentialOffer offer = store.find(offerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown credential offer"));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(CredentialOfferWriter.write(offer).toString());
    }
}
