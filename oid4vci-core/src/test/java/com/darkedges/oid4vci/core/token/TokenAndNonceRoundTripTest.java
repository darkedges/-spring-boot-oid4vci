package com.darkedges.oid4vci.core.token;

import com.darkedges.oid4vci.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Round-trips against fixtures transcribed verbatim from OID4VCI 1.0 (confirmed via independent
 * research, not paraphrased): the Section 6.2 Token Response example and the Section 7 Nonce Response
 * example. */
class TokenAndNonceRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parsesTheSpecsTokenResponseExample() {
        JsonNode json = FixtureLoader.readJson("token_response.json");

        TokenResponse response = TokenResponseReader.read(json);

        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).contains(86400L);
        assertThat(response.authorizationDetails()).isPresent();
        AuthorizationDetail detail = response.authorizationDetails().get().get(0);
        assertThat(detail.credentialConfigurationId()).isEqualTo("UniversityDegreeCredential");
        assertThat(detail.credentialIdentifiers()).contains(
                java.util.List.of("CivilEngineeringDegree-2023", "ElectricalEngineeringDegree-2023"));
    }

    @Test
    void tokenResponseWritingThenReadingBackProducesAnEquivalentDocument() throws Exception {
        JsonNode original = FixtureLoader.readJson("token_response.json");
        TokenResponse response = TokenResponseReader.read(original);

        JsonNode written = TokenResponseWriter.write(response);

        assertThat(TokenResponseReader.read(written)).isEqualTo(response);
        assertThat(MAPPER.readTree(MAPPER.writeValueAsString(written))).isEqualTo(original);
    }

    @Test
    void parsesTheSpecsNonceResponseExample() {
        JsonNode json = FixtureLoader.readJson("nonce_response.json");

        NonceResponse response = NonceResponseReader.read(json);

        assertThat(response.cNonce()).isEqualTo("wKI4LT17ac15ES9bw8ac4");
        assertThat(NonceResponseWriter.write(response).get("c_nonce").asText()).isEqualTo("wKI4LT17ac15ES9bw8ac4");
    }
}
