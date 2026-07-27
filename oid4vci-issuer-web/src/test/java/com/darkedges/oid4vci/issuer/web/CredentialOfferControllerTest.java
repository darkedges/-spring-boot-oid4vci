package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.issuer.InMemoryCredentialOfferStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialOfferControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void servesAPreviouslySavedOffer() throws Exception {
        InMemoryCredentialOfferStore store = new InMemoryCredentialOfferStore();
        CredentialOffer offer = new CredentialOffer(
                URI.create("https://issuer.example.org"), List.of("UniversityDegreeCredential"), Optional.empty());
        store.save("offer-1", offer);

        var response = new CredentialOfferController(store).offer("offer-1");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(MAPPER.readTree(response.getBody()).get("credential_issuer").asText()).isEqualTo("https://issuer.example.org");
    }

    @Test
    void respondsNotFoundForAnUnknownOfferId() {
        CredentialOfferController controller = new CredentialOfferController(new InMemoryCredentialOfferStore());

        assertThatThrownBy(() -> controller.offer("does-not-exist")).isInstanceOf(ResponseStatusException.class);
    }
}
