package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.AttestationChallengeService;
import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.NonceService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class ChallengeControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void issuesAFreshChallengeWithNoStoreCaching() throws Exception {
        ChallengeController controller = new ChallengeController(
                new AttestationChallengeService(new NonceService(new InMemoryNonceStore(), Clock.systemUTC(), Duration.ofMinutes(5))));

        var response = controller.challenge();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(MAPPER.readTree(response.getBody()).get("attestation_challenge").asText()).isNotBlank();
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
    }
}
