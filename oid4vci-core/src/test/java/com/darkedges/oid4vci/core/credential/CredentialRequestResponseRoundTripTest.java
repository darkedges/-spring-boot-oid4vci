package com.darkedges.oid4vci.core.credential;

import com.darkedges.oid4vci.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code credential_request.json} is transcribed verbatim from OID4VCI 1.0 Section 8.2's worked example
 * (confirmed by independently decoding its proof JWT's base64url header — see
 * {@link com.darkedges.oid4vci.core.proof.ProofOfPossessionJwt}'s Javadoc). {@code credential_response.json}
 * is a representative example, not a spec quote (repeated fetch attempts for Section 8.3 returned only
 * truncated text) — but its {@code credentials: [{"credential": "..."}]} wrapper-object shape (not a
 * plain array of strings, an earlier draft of this model incorrectly assumed) was independently
 * confirmed via search before this fixture/model was written.
 */
class CredentialRequestResponseRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parsesTheSpecsCredentialRequestExample() {
        JsonNode json = FixtureLoader.readJson("credential_request.json");

        CredentialRequest request = CredentialRequestReader.read(json);

        assertThat(request.credentialIdentifier()).contains("CivilEngineeringDegree-2023");
        assertThat(request.credentialConfigurationId()).isEmpty();
        assertThat(request.proofs()).isPresent();
        assertThat(request.proofs().get().jwt()).isPresent();
        assertThat(request.proofs().get().jwt().get()).hasSize(1);
    }

    @Test
    void credentialRequestWritingThenReadingBackProducesAnEquivalentDocument() throws Exception {
        JsonNode original = FixtureLoader.readJson("credential_request.json");
        CredentialRequest request = CredentialRequestReader.read(original);

        JsonNode written = CredentialRequestWriter.write(request);

        assertThat(CredentialRequestReader.read(written)).isEqualTo(request);
        assertThat(MAPPER.readTree(MAPPER.writeValueAsString(written))).isEqualTo(original);
    }

    @Test
    void parsesACredentialResponseWithTheWrapperObjectShape() {
        JsonNode json = FixtureLoader.readJson("credential_response.json");

        CredentialResponse response = CredentialResponseReader.read(json);

        assertThat(response.credentials()).isPresent();
        assertThat(response.credentials().get()).hasSize(1);
        assertThat(response.credentials().get().get(0).credential()).startsWith("eyJhbGciOiJFUzI1NiJ9");
        assertThat(response.transactionId()).isEmpty();
    }

    @Test
    void credentialResponseWritingThenReadingBackProducesAnEquivalentDocument() throws Exception {
        JsonNode original = FixtureLoader.readJson("credential_response.json");
        CredentialResponse response = CredentialResponseReader.read(original);

        JsonNode written = CredentialResponseWriter.write(response);

        assertThat(CredentialResponseReader.read(written)).isEqualTo(response);
        assertThat(MAPPER.readTree(MAPPER.writeValueAsString(written))).isEqualTo(original);
    }
}
