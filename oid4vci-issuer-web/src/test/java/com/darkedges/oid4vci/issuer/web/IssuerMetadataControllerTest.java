package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class IssuerMetadataControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void servesTheMetadataDocumentAsJson() throws Exception {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.example.org");
        request.setServerPort(443);

        var response = new IssuerMetadataController(template).metadata(request);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("credential_issuer").asText()).isEqualTo("https://issuer.example.org");
        assertThat(body.get("credential_configurations_supported").has("UniversityDegreeCredential")).isTrue();
    }
}
