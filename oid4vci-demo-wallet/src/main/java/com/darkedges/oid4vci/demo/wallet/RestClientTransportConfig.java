package com.darkedges.oid4vci.demo.wallet;

import com.darkedges.oid4vci.core.credential.CredentialRequestWriter;
import com.darkedges.oid4vci.core.credential.CredentialResponseReader;
import com.darkedges.oid4vci.core.token.GrantType;
import com.darkedges.oid4vci.core.token.NonceResponseReader;
import com.darkedges.oid4vci.core.token.TokenResponseReader;
import com.darkedges.oid4vci.wallet.CredentialEndpointClient;
import com.darkedges.oid4vci.wallet.NonceEndpointClient;
import com.darkedges.oid4vci.wallet.PreAuthorizedTokenEndpointClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * {@code RestClient}-based transport implementations for {@code oid4vci-wallet-core}'s three client
 * interfaces — mirrors {@code oid4vp-demo-verifier}'s own {@code TokenEndpointClient} bean shape.
 *
 * <p>Every response is fetched as a raw {@code String} and parsed manually with this module's own
 * Jackson-2 {@link ObjectMapper} + {@code oid4vci-core}'s {@code *Reader} classes, deliberately never via
 * {@code RestClient.retrieve().body(SomeType.class)} — that path goes through Spring's auto-configured
 * message converters, which under Spring Boot 4.1 include a Jackson-3 one that doesn't recognize
 * Jackson-2 types (the same issue documented in the project README for the server side of
 * {@code oid4vci-issuer-web}, confirmed live there before this class was written).
 */
@Configuration
public class RestClientTransportConfig {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Bean
    public PreAuthorizedTokenEndpointClient preAuthorizedTokenEndpointClient() {
        RestClient restClient = RestClient.create();
        return (tokenEndpoint, preAuthorizedCode, txCode) -> {
            StringBuilder form = new StringBuilder("grant_type=")
                    .append(URLEncoder.encode(GrantType.PRE_AUTHORIZED_CODE.value(), StandardCharsets.UTF_8))
                    .append("&pre-authorized_code=")
                    .append(URLEncoder.encode(preAuthorizedCode, StandardCharsets.UTF_8));
            txCode.ifPresent(code -> form.append("&tx_code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8)));

            String body = restClient.post()
                    .uri(tokenEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form.toString())
                    .retrieve()
                    .body(String.class);
            return parse(body, TokenResponseReader::read, "token response");
        };
    }

    @Bean
    public NonceEndpointClient nonceEndpointClient() {
        RestClient restClient = RestClient.create();
        return nonceEndpoint -> {
            String body = restClient.post().uri(nonceEndpoint).retrieve().body(String.class);
            return parse(body, NonceResponseReader::read, "nonce response").cNonce();
        };
    }

    @Bean
    public CredentialEndpointClient credentialEndpointClient() {
        RestClient restClient = RestClient.create();
        return (credentialEndpoint, accessToken, request) -> {
            String requestBody = CredentialRequestWriter.write(request).toString();
            String body = restClient.post()
                    .uri(credentialEndpoint)
                    .header("Authorization", "Bearer " + accessToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(requestBody)
                    .retrieve()
                    .body(String.class);
            return parse(body, CredentialResponseReader::read, "credential response");
        };
    }

    private static <T> T parse(String body, JsonParser<T> reader, String description) {
        try {
            return reader.read(MAPPER.readTree(body));
        } catch (Exception e) {
            throw new IllegalStateException("failed to parse " + description + ": " + body, e);
        }
    }

    @FunctionalInterface
    private interface JsonParser<T> {
        T read(JsonNode node) throws Exception;
    }
}
