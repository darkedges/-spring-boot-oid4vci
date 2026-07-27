package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class IssuerMetadataControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void servesTheMetadataDocumentAsJson() throws Exception {
        CredentialIssuerMetadata metadata = new CredentialIssuerMetadata(
                URI.create("https://issuer.example.org"), URI.create("https://issuer.example.org/credential"),
                Optional.of(URI.create("https://issuer.example.org/nonce")), Optional.empty(), List.of(),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of())));

        var response = new IssuerMetadataController(metadata).metadata();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("credential_issuer").asText()).isEqualTo("https://issuer.example.org");
        assertThat(body.get("credential_configurations_supported").has("UniversityDegreeCredential")).isTrue();
    }
}
