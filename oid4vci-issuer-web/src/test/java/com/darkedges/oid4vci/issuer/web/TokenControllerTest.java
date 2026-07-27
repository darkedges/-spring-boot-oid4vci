package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.InMemoryIssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.InMemoryPreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenControllerTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void redeemsAValidCodeAndPersistsItsClaimsForTheCredentialEndpointToFindLater() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(),
                Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))));
        AccessTokenService accessTokenService = new AccessTokenService(issuerKey, "https://issuer.example.org", Duration.ofMinutes(5), CLOCK);
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), accessTokenService, claimsStore);

        var response = controller.token(Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        String accessToken = MAPPER.readTree(response.getBody()).get("access_token").asText();
        AccessTokenService.AccessTokenClaims verified = accessTokenService.verify(accessToken);
        assertThat(claimsStore.find(verified.subject())).contains(Map.of("given_name", "Jane"));
    }

    @Test
    void rejectsAnUnknownCode() {
        ECKey issuerKey = generateKey();
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(new InMemoryPreAuthorizedCodeStore(), CLOCK),
                new AccessTokenService(issuerKey, "https://issuer.example.org", Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore());

        assertThatThrownBy(() -> controller.token(Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "no-such-code")))
                .isInstanceOf(Oid4vciException.class);
    }

    private static ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
