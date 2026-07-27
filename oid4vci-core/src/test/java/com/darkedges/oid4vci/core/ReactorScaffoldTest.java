package com.darkedges.oid4vci.core;

import com.darkedges.oid4vci.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Not a real domain-model test (that's Phase 2) -- exists only to prove the reactor scaffold actually
 * works end to end: this module resolves oid4vp-core as a Maven dependency from the sibling reactor, and
 * oid4vci-test-fixtures' FixtureLoader can read a transcribed spec fixture off the classpath.
 */
class ReactorScaffoldTest {

    @Test
    void resolvesTheSiblingOid4vpCoreDependency() {
        assertThat(CredentialFormat.DC_SD_JWT.identifier()).isEqualTo("dc+sd-jwt");
        assertThat(CredentialFormat.fromIdentifier("vc+sd-jwt")).isEqualTo(CredentialFormat.DC_SD_JWT);
    }

    @Test
    void readsATranscribedFixtureOffTheClasspath() {
        JsonNode offer = FixtureLoader.readJson("credential_offer_pre_authorized_code.json");
        assertThat(offer.get("credential_issuer").asText()).isEqualTo("https://credential-issuer.example.com");
        assertThat(offer.get("credential_configuration_ids")).hasSize(2);
    }
}
