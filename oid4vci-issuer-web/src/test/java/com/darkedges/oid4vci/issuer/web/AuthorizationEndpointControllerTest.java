package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.issuer.AuthorizationClaimsResolver;
import com.darkedges.oid4vci.issuer.AuthorizationCodeEntry;
import com.darkedges.oid4vci.issuer.AuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.InMemoryAuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.InMemoryPushedAuthorizationRequestStore;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationEndpointControllerTest {

    private static final String REDIRECT_URI = "https://wallet.example.org/callback";
    private static final String VERIFIER = "a-code-verifier-that-is-at-least-forty-three-characters-long";

    @Test
    void redirectsWithACodeAndEchoesStateOnAWellFormedRequest() throws Exception {
        AuthorizationCodeStore codeStore = new InMemoryAuthorizationCodeStore();
        AuthorizationEndpointController controller = controller(codeStore, claims -> Map.of("given_name", "Jane"));

        var response = controller.authorize(baseParams("xyz-state"), request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        URI location = response.getHeaders().getLocation();
        assertThat(location).isNotNull();
        Map<String, String> query = parseQuery(location);
        assertThat(query).containsKey("code");
        assertThat(query).containsEntry("state", "xyz-state");
        assertThat(query).containsEntry("iss", "https://issuer.example.org");

        AuthorizationCodeEntry entry = codeStore.consume(query.get("code")).orElseThrow();
        assertThat(entry.redirectUri()).isEqualTo(URI.create(REDIRECT_URI));
        assertThat(entry.session().claims()).containsEntry("given_name", "Jane");
        assertThat(entry.session().credentialConfigurationIds()).containsExactly("UniversityDegreeCredential");
    }

    @Test
    void respondsDirectlyWith400WhenRedirectUriIsMissing() {
        AuthorizationEndpointController controller = controller(new InMemoryAuthorizationCodeStore(), claims -> Map.of());

        Map<String, String> params = new HashMap<>();
        params.put("response_type", "code");
        params.put("client_id", "wallet-1");

        var response = controller.authorize(params, request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void redirectsWithInvalidRequestWhenPkceIsMissing() {
        AuthorizationEndpointController controller = controller(new InMemoryAuthorizationCodeStore(), claims -> Map.of());

        Map<String, String> params = new HashMap<>();
        params.put("response_type", "code");
        params.put("client_id", "wallet-1");
        params.put("redirect_uri", REDIRECT_URI);

        var response = controller.authorize(params, request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        Map<String, String> query = parseQuery(response.getHeaders().getLocation());
        assertThat(query).containsEntry("error", "invalid_request");
    }

    @Test
    void redirectsWithUnsupportedResponseTypeForAnythingOtherThanCode() {
        AuthorizationEndpointController controller = controller(new InMemoryAuthorizationCodeStore(), claims -> Map.of());

        Map<String, String> params = baseParams(null);
        params.put("response_type", "token");

        var response = controller.authorize(params, request());

        Map<String, String> query = parseQuery(response.getHeaders().getLocation());
        assertThat(query).containsEntry("error", "unsupported_response_type");
    }

    @Test
    void redirectsWithInvalidRequestForAnUnknownCredentialConfigurationId() {
        AuthorizationEndpointController controller = controller(new InMemoryAuthorizationCodeStore(), claims -> Map.of());

        Map<String, String> params = baseParams(null);
        params.put("authorization_details", "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"NoSuchCredential\"}]");

        var response = controller.authorize(params, request());

        Map<String, String> query = parseQuery(response.getHeaders().getLocation());
        assertThat(query).containsEntry("error", "invalid_request");
    }

    @Test
    void resolvesCredentialConfigurationIdsFromScopeWhenAuthorizationDetailsAreAbsent() throws Exception {
        AuthorizationCodeStore codeStore = new InMemoryAuthorizationCodeStore();
        AuthorizationEndpointController controller = controller(codeStore, claims -> Map.of());

        Map<String, String> params = baseParams(null);
        params.put("scope", "UniversityDegreeCredential");

        var response = controller.authorize(params, request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        Map<String, String> query = parseQuery(response.getHeaders().getLocation());
        AuthorizationCodeEntry entry = codeStore.consume(query.get("code")).orElseThrow();
        assertThat(entry.session().credentialConfigurationIds()).containsExactly("UniversityDegreeCredential");
    }

    @Test
    void redirectsWithInvalidScopeForAnUnknownScopeToken() {
        AuthorizationEndpointController controller = controller(new InMemoryAuthorizationCodeStore(), claims -> Map.of());

        Map<String, String> params = baseParams(null);
        params.put("scope", "NoSuchScope");

        var response = controller.authorize(params, request());

        Map<String, String> query = parseQuery(response.getHeaders().getLocation());
        assertThat(query).containsEntry("error", "invalid_scope");
    }

    @Test
    void resolvesAPushedRequestUriAndConsumesItOnce() throws Exception {
        AuthorizationCodeStore codeStore = new InMemoryAuthorizationCodeStore();
        PushedAuthorizationRequestStore pushedRequestStore = new InMemoryPushedAuthorizationRequestStore();
        AuthorizationEndpointController controller = controller(codeStore, pushedRequestStore, claims -> Map.of());

        com.darkedges.oid4vci.core.authorize.AuthorizationRequest pushed = new com.darkedges.oid4vci.core.authorize.AuthorizationRequest(
                "code", "wallet-1", URI.create(REDIRECT_URI), Optional.of("par-state"),
                Optional.of(s256(VERIFIER)), Optional.of("S256"), List.of(), List.of());
        pushedRequestStore.save("urn:ietf:params:oauth:request_uri:abc123",
                new PushedAuthorizationRequestEntry(pushed, Instant.now().plus(Duration.ofSeconds(60))));

        Map<String, String> params = new HashMap<>();
        params.put("request_uri", "urn:ietf:params:oauth:request_uri:abc123");
        params.put("client_id", "wallet-1");

        var response = controller.authorize(params, request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        Map<String, String> query = parseQuery(response.getHeaders().getLocation());
        assertThat(query).containsEntry("state", "par-state");
        assertThat(query).containsEntry("iss", "https://issuer.example.org");
        AuthorizationCodeEntry entry = codeStore.consume(query.get("code")).orElseThrow();
        assertThat(entry.session().credentialConfigurationIds()).containsExactly("UniversityDegreeCredential");

        // single-use: presenting the same request_uri again must fail
        var second = controller.authorize(params, request());
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void respondsDirectlyWith400ForAnUnknownRequestUri() {
        AuthorizationEndpointController controller = controller(
                new InMemoryAuthorizationCodeStore(), new InMemoryPushedAuthorizationRequestStore(), claims -> Map.of());

        Map<String, String> params = new HashMap<>();
        params.put("request_uri", "urn:ietf:params:oauth:request_uri:no-such-request");
        params.put("client_id", "wallet-1");

        var response = controller.authorize(params, request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void respondsDirectlyWith400WhenClientIdDoesNotMatchThePushedRequest() throws Exception {
        PushedAuthorizationRequestStore pushedRequestStore = new InMemoryPushedAuthorizationRequestStore();
        AuthorizationEndpointController controller = controller(
                new InMemoryAuthorizationCodeStore(), pushedRequestStore, claims -> Map.of());

        com.darkedges.oid4vci.core.authorize.AuthorizationRequest pushed = new com.darkedges.oid4vci.core.authorize.AuthorizationRequest(
                "code", "wallet-1", URI.create(REDIRECT_URI), Optional.empty(),
                Optional.of(s256(VERIFIER)), Optional.of("S256"), List.of(), List.of());
        pushedRequestStore.save("urn:ietf:params:oauth:request_uri:abc123",
                new PushedAuthorizationRequestEntry(pushed, Instant.now().plus(Duration.ofSeconds(60))));

        Map<String, String> params = new HashMap<>();
        params.put("request_uri", "urn:ietf:params:oauth:request_uri:abc123");
        params.put("client_id", "a-different-wallet");

        var response = controller.authorize(params, request());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    private static AuthorizationEndpointController controller(AuthorizationCodeStore store, AuthorizationClaimsResolver resolver) {
        return controller(store, new InMemoryPushedAuthorizationRequestStore(), resolver);
    }

    private static AuthorizationEndpointController controller(
            AuthorizationCodeStore store, PushedAuthorizationRequestStore pushedRequestStore, AuthorizationClaimsResolver resolver) {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(),
                        Optional.of("UniversityDegreeCredential"))));
        return new AuthorizationEndpointController(store, pushedRequestStore, template, resolver);
    }

    private static Map<String, String> baseParams(String state) {
        Map<String, String> params = new HashMap<>();
        params.put("response_type", "code");
        params.put("client_id", "wallet-1");
        params.put("redirect_uri", REDIRECT_URI);
        params.put("code_challenge", s256(VERIFIER));
        params.put("code_challenge_method", "S256");
        if (state != null) {
            params.put("state", state);
        }
        return params;
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("issuer.example.org");
        request.setServerPort(443);
        return request;
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> params = new HashMap<>();
        if (uri.getRawQuery() == null) {
            return params;
        }
        for (String pair : uri.getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            params.put(parts[0], URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
        }
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
