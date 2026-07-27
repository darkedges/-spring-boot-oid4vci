package com.darkedges.oid4vci.core.offer;

import com.darkedges.oid4vci.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trips {@link CredentialOfferReader}/{@link CredentialOfferWriter} against the worked example
 * transcribed verbatim from OID4VCI 1.0 Section 4.1.1 (confirmed by independently fetching and quoting
 * the spec's own JSON code block, not paraphrased).
 */
class CredentialOfferRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parsesTheSpecsPreAuthorizedCodeExample() {
        JsonNode json = FixtureLoader.readJson("credential_offer_pre_authorized_code.json");

        CredentialOffer offer = CredentialOfferReader.read(json);

        assertThat(offer.credentialIssuer().toString()).isEqualTo("https://credential-issuer.example.com");
        assertThat(offer.credentialConfigurationIds())
                .containsExactly("UniversityDegreeCredential", "org.iso.18013.5.1.mDL");
        assertThat(offer.grants()).isPresent();
        PreAuthorizedCodeGrant grant = offer.grants().get().preAuthorizedCode().orElseThrow();
        assertThat(grant.preAuthorizedCode()).isEqualTo("oaKazRN8I0IbtZ0C7JuMn5");
        assertThat(grant.txCode()).isPresent();
        assertThat(grant.txCode().get().inputMode()).contains(TxCodeInputMode.NUMERIC);
        assertThat(grant.txCode().get().length()).contains(4);
        assertThat(grant.txCode().get().description())
                .contains("Please provide the one-time code that was sent via e-mail");
    }

    @Test
    void writingThenReadingBackProducesAnEquivalentOffer() throws Exception {
        JsonNode original = FixtureLoader.readJson("credential_offer_pre_authorized_code.json");
        CredentialOffer offer = CredentialOfferReader.read(original);

        JsonNode written = CredentialOfferWriter.write(offer);
        CredentialOffer reparsed = CredentialOfferReader.read(written);

        assertThat(reparsed).isEqualTo(offer);
        assertThat(MAPPER.readTree(MAPPER.writeValueAsString(written))).isEqualTo(original);
    }
}
