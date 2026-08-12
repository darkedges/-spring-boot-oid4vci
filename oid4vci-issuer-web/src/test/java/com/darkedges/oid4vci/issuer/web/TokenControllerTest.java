package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.dpop.DpopProof;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.AuthorizationCodeEntry;
import com.darkedges.oid4vci.issuer.AuthorizationCodeService;
import com.darkedges.oid4vci.issuer.AuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.ClientAttestationTrustAnchor;
import com.darkedges.oid4vci.issuer.ClientAttestationValidator;
import com.darkedges.oid4vci.issuer.DpopProofValidator;
import com.darkedges.oid4vci.issuer.InMemoryAuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.InMemoryDpopReplayStore;
import com.darkedges.oid4vci.issuer.InMemoryIssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.InMemoryPreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenControllerTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE_URL = "https://issuer.example.org";
    private static final String TOKEN_ENDPOINT_URL = BASE_URL + "/token";

    @Test
    void redeemsAValidCodeAndPersistsItsClaimsForTheCredentialEndpointToFindLater() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(),
                Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))));
        AccessTokenService accessTokenService = new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK);
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), accessTokenService, claimsStore, dpopProofValidator(), Optional.empty(), Optional.empty());

        var response = controller.token(Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"),
                null, null, null, request(BASE_URL));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        String accessToken = MAPPER.readTree(response.getBody()).get("access_token").asText();
        AccessTokenService.AccessTokenClaims verified = accessTokenService.verify(accessToken);
        assertThat(claimsStore.find(verified.subject(), CLOCK.instant())).contains(Map.of("given_name", "Jane"));
    }

    @Test
    void rejectsAnUnknownCode() {
        ECKey issuerKey = generateKey();
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(new InMemoryPreAuthorizedCodeStore(), CLOCK),
                new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(), Optional.empty(), Optional.empty());

        assertThatThrownBy(() -> controller.token(Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "no-such-code"),
                null, null, null, request(BASE_URL)))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void bindsTheAccessTokenToTheWalletsDpopKeyWhenADpopProofIsPresented() throws Exception {
        ECKey issuerKey = generateKey();
        ECKey walletKey = generateKey();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(),
                Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))));
        AccessTokenService accessTokenService = new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK);
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), accessTokenService, new InMemoryIssuedAccessTokenClaimsStore(),
                dpopProofValidator(), Optional.empty(), Optional.empty());

        var response = controller.token(Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"),
                dpopProof(walletKey, "POST", TOKEN_ENDPOINT_URL), null, null, request(BASE_URL));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        String accessToken = MAPPER.readTree(response.getBody()).get("access_token").asText();
        SignedJWT jwt = SignedJWT.parse(accessToken);
        Map<String, Object> cnf = (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("cnf");
        assertThat(cnf).containsEntry("jkt", DpopProofValidator.computeThumbprint(walletKey));
    }

    @Test
    void rejectsATokenRequestWhoseDpopProofIsForADifferentEndpoint() {
        ECKey issuerKey = generateKey();
        ECKey walletKey = generateKey();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(),
                Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))));
        AccessTokenService accessTokenService = new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK);
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), accessTokenService, new InMemoryIssuedAccessTokenClaimsStore(),
                dpopProofValidator(), Optional.empty(), Optional.empty());

        assertThatThrownBy(() -> controller.token(Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"),
                dpopProof(walletKey, "POST", "https://issuer.example.org/credential"), null, null, request(BASE_URL)))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void authenticatesTheClientViaAttestationBasedClientAuthWhenBothHeadersAreValid() throws Exception {
        ECKey issuerKey = generateKey();
        ECKey walletProviderKey = generateKey();
        ECKey walletInstanceKey = generateKey();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(),
                Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))));
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(),
                Optional.of(clientAttestationValidator(walletProviderKey)), Optional.empty());

        var response = controller.token(Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"),
                null, attestationJwt(walletProviderKey, walletInstanceKey), popJwt(walletInstanceKey, BASE_URL),
                request(BASE_URL));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    @Test
    void rejectsATokenRequestWithOnlyOneOfTheTwoAttestationHeaders() throws Exception {
        ECKey issuerKey = generateKey();
        ECKey walletProviderKey = generateKey();
        ECKey walletInstanceKey = generateKey();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(), Map.of(), CLOCK.instant().plus(Duration.ofMinutes(10))));
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(),
                Optional.of(clientAttestationValidator(walletProviderKey)), Optional.empty());

        assertThatThrownBy(() -> controller.token(Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"),
                null, attestationJwt(walletProviderKey, walletInstanceKey), null, request(BASE_URL)))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAttestationHeadersWhenTheIssuerHasNoTrustAnchorConfigured() throws Exception {
        ECKey issuerKey = generateKey();
        ECKey walletProviderKey = generateKey();
        ECKey walletInstanceKey = generateKey();
        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), Optional.empty(), Map.of(), CLOCK.instant().plus(Duration.ofMinutes(10))));
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(codeStore, CLOCK), new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(), Optional.empty(), Optional.empty());

        assertThatThrownBy(() -> controller.token(Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", "the-code"),
                null, attestationJwt(walletProviderKey, walletInstanceKey), popJwt(walletInstanceKey, BASE_URL),
                request(BASE_URL)))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void redeemsAValidAuthorizationCodeIncludingItsPkceVerifier() throws Exception {
        ECKey issuerKey = generateKey();
        String redirectUri = "https://wallet.example.org/callback";
        String verifier = "a-code-verifier-that-is-at-least-forty-three-characters-long";
        AuthorizationCodeStore codeStore = new InMemoryAuthorizationCodeStore();
        codeStore.save("the-code", new AuthorizationCodeEntry(
                new PreAuthorizedCodeSession(
                        List.of("UniversityDegreeCredential"), Optional.empty(),
                        Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))),
                URI.create(redirectUri), Optional.of(s256(verifier)), Optional.of("S256")));
        AccessTokenService accessTokenService = new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK);
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(new InMemoryPreAuthorizedCodeStore(), CLOCK), accessTokenService,
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(), Optional.empty(),
                Optional.of(new AuthorizationCodeService(codeStore, CLOCK)));

        var response = controller.token(Map.of(
                        "grant_type", "authorization_code", "code", "the-code",
                        "redirect_uri", redirectUri, "code_verifier", verifier),
                null, null, null, request(BASE_URL));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    @Test
    void rejectsAnAuthorizationCodeWithTheWrongPkceVerifier() throws Exception {
        ECKey issuerKey = generateKey();
        String redirectUri = "https://wallet.example.org/callback";
        AuthorizationCodeStore codeStore = new InMemoryAuthorizationCodeStore();
        codeStore.save("the-code", new AuthorizationCodeEntry(
                new PreAuthorizedCodeSession(
                        List.of("UniversityDegreeCredential"), Optional.empty(),
                        Map.of("given_name", "Jane"), CLOCK.instant().plus(Duration.ofMinutes(10))),
                URI.create(redirectUri), Optional.of(s256("the-real-verifier")), Optional.of("S256")));
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(new InMemoryPreAuthorizedCodeStore(), CLOCK),
                new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(), Optional.empty(),
                Optional.of(new AuthorizationCodeService(codeStore, CLOCK)));

        assertThatThrownBy(() -> controller.token(Map.of(
                        "grant_type", "authorization_code", "code", "the-code",
                        "redirect_uri", redirectUri, "code_verifier", "not-the-real-verifier"),
                null, null, null, request(BASE_URL)))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAnUnsupportedGrantType() {
        ECKey issuerKey = generateKey();
        TokenController controller = new TokenController(
                new PreAuthorizedCodeService(new InMemoryPreAuthorizedCodeStore(), CLOCK),
                new AccessTokenService(issuerKey, Duration.ofMinutes(5), CLOCK),
                new InMemoryIssuedAccessTokenClaimsStore(), dpopProofValidator(), Optional.empty(), Optional.empty());

        assertThatThrownBy(() -> controller.token(Map.of("grant_type", "client_credentials"),
                null, null, null, request(BASE_URL)))
                .isInstanceOf(Oid4vciException.class);
    }

    private static String s256(String verifier) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private static DpopProofValidator dpopProofValidator() {
        return new DpopProofValidator(new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1));
    }

    private static ClientAttestationValidator clientAttestationValidator(ECKey trustedWalletProviderKey) {
        return new ClientAttestationValidator(
                new ClientAttestationTrustAnchor("https://wallet-provider.example.org", trustedWalletProviderKey.toPublicJWK()),
                new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1));
    }

    private static String attestationJwt(ECKey walletProviderKey, ECKey walletInstanceKey) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://wallet-provider.example.org")
                .subject("wallet-instance-1")
                .expirationTime(Date.from(CLOCK.instant().plus(Duration.ofMinutes(10))))
                .claim("cnf", Map.of("jwk", walletInstanceKey.toPublicJWK().toJSONObject()))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ClientAttestation.ATTESTATION_TYP))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletProviderKey));
        return jwt.serialize();
    }

    private static String popJwt(ECKey walletInstanceKey, String audience) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("wallet-instance-1")
                .audience(audience)
                .issueTime(Date.from(CLOCK.instant()))
                .jwtID(UUID.randomUUID().toString())
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ClientAttestation.ATTESTATION_POP_TYP))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(walletInstanceKey));
        return jwt.serialize();
    }

    private static MockHttpServletRequest request(String baseUrl) {
        URI uri = URI.create(baseUrl);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(uri.getScheme());
        request.setServerName(uri.getHost());
        request.setServerPort(uri.getPort() == -1 ? ("https".equals(uri.getScheme()) ? 443 : 80) : uri.getPort());
        return request;
    }

    static String dpopProof(ECKey key, String htm, String htu) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", htm)
                .claim("htu", htu)
                .issueTime(Date.from(CLOCK.instant()))
                .jwtID(UUID.randomUUID().toString())
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(DpopProof.TYP))
                .jwk(key.toPublicJWK())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
