package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.MsoMdocCredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtVcTypeMetadataControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.zkp.au");
        request.setServerPort(443);
        return request;
    }

    @Test
    void servesTypeMetadataWithTheSameResolvedVctAsTheIssuerMetadata() throws Exception {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.empty(),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "/vct/UniversityDegreeCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));
        SdJwtVcTypeMetadataController controller = new SdJwtVcTypeMetadataController(template);

        var response = controller.typeMetadata("UniversityDegreeCredential", request());

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("vct").asText()).isEqualTo("https://issuer.zkp.au/vct/UniversityDegreeCredential");
    }

    @Test
    void returnsNotFoundForAnUnknownConfigurationId() {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.empty(),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "/vct/UniversityDegreeCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));
        SdJwtVcTypeMetadataController controller = new SdJwtVcTypeMetadataController(template);

        var response = controller.typeMetadata("NoSuchCredential", request());

        assertThat(response.getStatusCode().is4xxClientError()).isTrue();
    }

    @Test
    void returnsNotFoundForAConfigurationThatIsNotSdJwtVc() {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.empty(),
                Map.of("org.iso.18013.5.1.mDL", new MsoMdocCredentialConfiguration(
                        "org.iso.18013.5.1.mDL", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));
        SdJwtVcTypeMetadataController controller = new SdJwtVcTypeMetadataController(template);

        var response = controller.typeMetadata("org.iso.18013.5.1.mDL", request());

        assertThat(response.getStatusCode().is4xxClientError()).isTrue();
    }
}
