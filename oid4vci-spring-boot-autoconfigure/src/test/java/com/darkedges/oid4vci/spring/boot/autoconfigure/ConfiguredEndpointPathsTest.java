package com.darkedges.oid4vci.spring.boot.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** A configured endpoint path is where the endpoint answers, not only what the metadata advertises. */
class ConfiguredEndpointPathsTest {

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    static class Mvc {}

    @Test
    void theNonceAndChallengeEndpointsAnswerOnTheirConfiguredPathsAndTheMetadataSaysSo() {
        new WebApplicationContextRunner()
                .withUserConfiguration(Mvc.class)
                .withConfiguration(AutoConfigurations.of(Oid4vciIssuerAutoConfiguration.class))
                .withBean(ECKey.class, () -> {
                    try { return new ECKeyGenerator(Curve.P_256).keyID("k").generate(); } catch (Exception e) { throw new IllegalStateException(e); }
                })
                .withPropertyValues(
                        "oid4vci.issuer.credential-configurations-supported={\"C\":{\"format\":\"dc+sd-jwt\",\"vct\":\"https://vct.example/c\"}}",
                        "oid4vci.issuer.nonce-endpoint-path=/v2/nonce",
                        "oid4vci.issuer.credential-endpoint-path=/v2/credential",
                        "oid4vci.issuer.attestation-challenge-endpoint-path=/v2/challenge")
                .run(context -> {
                    MockMvc mvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) context).build();
                    mvc.perform(post("/v2/nonce")).andExpect(status().isOk());
                    mvc.perform(post("/nonce")).andExpect(status().isNotFound());
                    mvc.perform(post("/v2/challenge")).andExpect(status().isOk());

                    String metadata = mvc.perform(get("/.well-known/openid-credential-issuer").header("Host", "issuer.example"))
                            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
                    var json = new ObjectMapper().readTree(metadata);
                    assertThat(json.path("nonce_endpoint").asText()).endsWith("/v2/nonce");
                    assertThat(json.path("credential_endpoint").asText()).endsWith("/v2/credential");
                });
    }
}
