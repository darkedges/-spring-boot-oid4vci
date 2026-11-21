package com.darkedges.oid4vci.issuer.web;

import org.springframework.mock.web.MockHttpServletRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwksControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void servesThePublicKeyAsAJwkSetWithNoPrivateMaterial() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();

        var response = new JwksController(issuerKey).jwks(new MockHttpServletRequest());

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        var keys = MAPPER.readTree(response.getBody()).get("keys");
        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).get("kid").asText()).isEqualTo("issuer-1");
        assertThat(keys.get(0).has("d")).isFalse();
    }
}
