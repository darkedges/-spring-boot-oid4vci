package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.InMemoryPushedAuthorizationRequestStore;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PushedAuthorizationRequestControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String REDIRECT_URI = "https://wallet.example.org/callback";
    private static final String VERIFIER = "a-code-verifier-that-is-at-least-forty-three-characters-long";

    @Test
    void returns201WithARequestUriAndExpiresInOnAWellFormedRequest() throws Exception {
        PushedAuthorizationRequestStore store = new InMemoryPushedAuthorizationRequestStore();
        PushedAuthorizationRequestController controller = new PushedAuthorizationRequestController(store);

        var response = controller.pushAuthorizationRequest(baseParams());

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        JsonNode body = MAPPER.readTree(response.getBody());
        String requestUri = body.get("request_uri").asText();
        assertThat(requestUri).startsWith("urn:ietf:params:oauth:request_uri:");
        assertThat(body.get("expires_in").asLong()).isEqualTo(60L);

        PushedAuthorizationRequestEntry entry = store.consume(requestUri).orElseThrow();
        assertThat(entry.request().clientId()).isEqualTo("wallet-1");
        assertThat(entry.request().redirectUri().toString()).isEqualTo(REDIRECT_URI);
    }

    @Test
    void returns400JsonErrorWhenRedirectUriIsMissing() {
        PushedAuthorizationRequestController controller = new PushedAuthorizationRequestController(new InMemoryPushedAuthorizationRequestStore());

        Map<String, String> params = baseParams();
        params.remove("redirect_uri");

        var response = controller.pushAuthorizationRequest(params);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void returns400JsonErrorWhenPkceIsMissing() {
        PushedAuthorizationRequestController controller = new PushedAuthorizationRequestController(new InMemoryPushedAuthorizationRequestStore());

        Map<String, String> params = baseParams();
        params.remove("code_challenge");
        params.remove("code_challenge_method");

        var response = controller.pushAuthorizationRequest(params);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    private static Map<String, String> baseParams() {
        Map<String, String> params = new HashMap<>();
        params.put("response_type", "code");
        params.put("client_id", "wallet-1");
        params.put("redirect_uri", REDIRECT_URI);
        params.put("code_challenge", s256(VERIFIER));
        params.put("code_challenge_method", "S256");
        return params;
    }

    private static String s256(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
