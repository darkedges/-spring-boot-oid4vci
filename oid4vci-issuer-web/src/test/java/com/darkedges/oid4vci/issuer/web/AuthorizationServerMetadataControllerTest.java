package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataTemplate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationServerMetadataControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void servesTheMetadataDocumentBuiltFromTheRequestsOwnHost() throws Exception {
        AuthorizationServerMetadataTemplate template = new AuthorizationServerMetadataTemplate(
                "/token", "/jwks", Optional.empty(), Optional.empty(),
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                List.of(),
                List.of(),
                List.of("none"),
                List.of("ES256"),
                List.of("openid_credential"),
                List.of(),
                List.of(),
                Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.zkp.au");
        request.setServerPort(443);

        var response = new AuthorizationServerMetadataController(template).metadata(request);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("issuer").asText()).isEqualTo("https://issuer.zkp.au");
        assertThat(body.get("token_endpoint").asText()).isEqualTo("https://issuer.zkp.au/token");
        assertThat(body.get("jwks_uri").asText()).isEqualTo("https://issuer.zkp.au/jwks");
        assertThat(body.get("grant_types_supported").get(0).asText())
                .isEqualTo("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        assertThat(body.get("token_endpoint_auth_methods_supported").get(0).asText()).isEqualTo("none");
        assertThat(body.get("dpop_signing_alg_values_supported").get(0).asText()).isEqualTo("ES256");
        assertThat(body.get("authorization_details_types_supported").get(0).asText()).isEqualTo("openid_credential");
        assertThat(body.has("authorization_endpoint")).isFalse();
        assertThat(body.has("pushed_authorization_request_endpoint")).isFalse();
        assertThat(body.has("response_types_supported")).isFalse();
        assertThat(body.has("code_challenge_methods_supported")).isFalse();
        assertThat(body.has("client_attestation_signing_alg_values_supported")).isFalse();
        assertThat(body.has("client_attestation_pop_signing_alg_values_supported")).isFalse();
    }

    @Test
    void advertisesAttestJwtClientAuthAndItsSigningAlgsWhenSupported() throws Exception {
        AuthorizationServerMetadataTemplate template = new AuthorizationServerMetadataTemplate(
                "/token", "/jwks", Optional.empty(), Optional.empty(),
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                List.of(),
                List.of(),
                List.of("none", "attest_jwt_client_auth"),
                List.of("ES256"),
                List.of("openid_credential"),
                List.of("ES256"),
                List.of("ES256"),
                Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.zkp.au");
        request.setServerPort(443);

        var response = new AuthorizationServerMetadataController(template).metadata(request);

        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("token_endpoint_auth_methods_supported").get(1).asText()).isEqualTo("attest_jwt_client_auth");
        assertThat(body.get("client_attestation_signing_alg_values_supported").get(0).asText()).isEqualTo("ES256");
        assertThat(body.get("client_attestation_pop_signing_alg_values_supported").get(0).asText()).isEqualTo("ES256");
    }

    @Test
    void advertisesTheAuthorizationEndpointResponseTypesAndPkceMethodsWhenAuthorizationCodeIsSupported() throws Exception {
        AuthorizationServerMetadataTemplate template = new AuthorizationServerMetadataTemplate(
                "/token", "/jwks", Optional.of("/authorize"), Optional.of("/par"),
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code", "authorization_code"),
                List.of("code"),
                List.of("S256"),
                List.of("none"),
                List.of("ES256"),
                List.of("openid_credential"),
                List.of(),
                List.of(),
                Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.zkp.au");
        request.setServerPort(443);

        var response = new AuthorizationServerMetadataController(template).metadata(request);

        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("authorization_endpoint").asText()).isEqualTo("https://issuer.zkp.au/authorize");
        assertThat(body.get("pushed_authorization_request_endpoint").asText()).isEqualTo("https://issuer.zkp.au/par");
        assertThat(body.get("response_types_supported").get(0).asText()).isEqualTo("code");
        assertThat(body.get("code_challenge_methods_supported").get(0).asText()).isEqualTo("S256");
        assertThat(body.get("grant_types_supported").get(1).asText()).isEqualTo("authorization_code");
    }

    @Test
    void advertisesTheChallengeEndpointWhenConfigured() throws Exception {
        AuthorizationServerMetadataTemplate template = new AuthorizationServerMetadataTemplate(
                "/token", "/jwks", Optional.empty(), Optional.empty(),
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                List.of(),
                List.of(),
                List.of("none", "attest_jwt_client_auth"),
                List.of("ES256"),
                List.of("openid_credential"),
                List.of("ES256"),
                List.of("ES256"),
                Optional.of("/challenge"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.zkp.au");
        request.setServerPort(443);

        var response = new AuthorizationServerMetadataController(template).metadata(request);

        JsonNode body = MAPPER.readTree(response.getBody());
        assertThat(body.get("challenge_endpoint").asText()).isEqualTo("https://issuer.zkp.au/challenge");
    }
}
