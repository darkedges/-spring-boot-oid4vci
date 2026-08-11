package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.error.AttestationChallengeRequiredException;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.NonceService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Clock;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vciExceptionHandlerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Oid4vciExceptionHandler handler() {
        return new Oid4vciExceptionHandler(new NonceService(new InMemoryNonceStore(), Clock.systemUTC(), Duration.ofMinutes(5)));
    }

    @Test
    void mapsAGenericExceptionToItsErrorCodeWithNoCNonce() throws Exception {
        ResponseEntity<String> response = handler().handle(
                new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_CREDENTIAL_TYPE, "nope"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(MAPPER.readTree(response.getBody()).get("error").asText()).isEqualTo("unsupported_credential_type");
        assertThat(MAPPER.readTree(response.getBody()).has("c_nonce")).isFalse();
    }

    @Test
    void mapsInvalidTokenAndInvalidClientTo401() throws Exception {
        assertThat(handler().handle(new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "x")).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(handler().handle(new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, "x")).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void embedsAFreshCNonceForInvalidProofAndInvalidNonce() throws Exception {
        ResponseEntity<String> proofResponse = handler().handle(new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "x"));
        assertThat(MAPPER.readTree(proofResponse.getBody()).get("c_nonce").asText()).isNotBlank();

        ResponseEntity<String> nonceResponse = handler().handle(new Oid4vciException(Oid4vciErrorCode.INVALID_NONCE, "x"));
        assertThat(MAPPER.readTree(nonceResponse.getBody()).get("c_nonce").asText()).isNotBlank();
    }

    @Test
    void embedsAFreshChallengeInTheChallengeHeaderForAttestationChallengeRequired() throws Exception {
        ResponseEntity<String> response = handler().handle(
                new AttestationChallengeRequiredException("fresh-challenge-value", "missing challenge"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(MAPPER.readTree(response.getBody()).get("error").asText()).isEqualTo("use_attestation_challenge");
        assertThat(response.getHeaders().getFirst(ClientAttestation.CHALLENGE_HEADER_NAME)).isEqualTo("fresh-challenge-value");
    }
}
