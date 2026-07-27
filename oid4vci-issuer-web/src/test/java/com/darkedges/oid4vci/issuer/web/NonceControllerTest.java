package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.NonceService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class NonceControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void issuesAFreshNonceWithNoStoreCaching() throws Exception {
        NonceController controller = new NonceController(new NonceService(new InMemoryNonceStore(), Clock.systemUTC(), Duration.ofMinutes(5)));

        var response = controller.nonce();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(MAPPER.readTree(response.getBody()).get("c_nonce").asText()).isNotBlank();
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
    }
}
