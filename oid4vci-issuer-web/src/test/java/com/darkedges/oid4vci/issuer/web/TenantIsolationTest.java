package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.core.proof.ProofOfPossessionJwt;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.CredentialIssuanceServiceResolver;
import com.darkedges.oid4vci.issuer.DpopProofValidator;
import com.darkedges.oid4vci.issuer.InMemoryDpopReplayStore;
import com.darkedges.oid4vci.issuer.InMemoryIssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.InMemoryPreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.darkedges.oid4vci.issuer.IssuerMetadataTemplates;
import com.darkedges.oid4vci.issuer.NonceService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Two tenants on one issuer: what one issues (codes, tokens, nonces, the claims behind a token) is refused by the other, and each
 * signs with its own key under its own identifier.
 */
class TenantIsolationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CONFIGURATION = "EmployeeCredential";

    private final Map<String, ECKey> keyByTenant;
    private final IssuerKeys keys;
    /** Tenant by host, as the tenancy filter would resolve it: bank.issuer.test and shop.issuer.test. */
    private final IssuerContextResolver issuers = request -> new IssuerContext(
            request.getServerName().split("\\.")[0], "https://" + request.getServerName());

    private final InMemoryPreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
    private final PreAuthorizedCodeService codes = new PreAuthorizedCodeService(codeStore, Clock.systemUTC());
    private final NonceService nonces = new NonceService(new InMemoryNonceStore(), Clock.systemUTC(), Duration.ofMinutes(5));
    private final IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
    private final TokenController tokenController;
    private final CredentialController credentialController;

    TenantIsolationTest() throws Exception {
        keyByTenant = Map.of("bank", new ECKeyGenerator(Curve.P_256).keyID("bank-1").generate(),
                "shop", new ECKeyGenerator(Curve.P_256).keyID("shop-1").generate());
        keys = new IssuerKeys() {
            @Override public ECKey signingKey(IssuerContext context) { return keyByTenant.get(context.tenantId()); }
            @Override public List<ECKey> verificationKeys(IssuerContext context) { return List.of(keyByTenant.get(context.tenantId()).toPublicJWK()); }
        };
        AccessTokenService accessTokens = new AccessTokenService(keys, Duration.ofMinutes(5), Clock.systemUTC());
        tokenController = new TokenController(codes, accessTokens, claimsStore,
                new DpopProofValidator(new InMemoryDpopReplayStore(), Clock.systemUTC(), Duration.ofMinutes(5)),
                Optional.empty(), Optional.empty(), issuers);
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate("/credential", Optional.of("/nonce"),
                Map.of(CONFIGURATION, new SdJwtVcCredentialConfiguration("https://vct.example/employee", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));
        credentialController = new CredentialController(IssuerMetadataTemplates.fixed(template, null),
                new ProofOfPossessionValidator(nonces, Clock.systemUTC(), Duration.ofMinutes(5)), claimsStore,
                CredentialIssuanceServiceResolver.of(Map.of(CredentialFormat.DC_SD_JWT,
                        new SdJwtVcCredentialIssuanceService(keys, Duration.ofDays(30), Clock.systemUTC()))),
                issuers, Clock.systemUTC());
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static MockHttpServletRequest at(String tenant) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName(tenant + ".issuer.test");
        request.setServerPort(443);
        return request;
    }

    private IssuerContext context(String tenant) {
        return issuers.resolve(at(tenant));
    }

    private void offer(String tenant, String code) {
        codes.offer(context(tenant), code, new PreAuthorizedCodeSession(List.of(CONFIGURATION), Optional.empty(),
                Map.of("given_name", "Jane"), Instant.now().plusSeconds(300)));
    }

    private JsonNode token(String tenant, String code) throws Exception {
        var response = tokenController.token(Map.of("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code", code), null, null, null, at(tenant));
        return MAPPER.readTree(response.getBody());
    }

    private Jwt decodeAt(String tenant, String accessToken) {
        HttpServletRequest request = at(tenant);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return new IssuerAccessTokenDecoder(keys, issuers, true).decode(accessToken);
    }

    private static String proof(ECKey holder, String audience, String nonce) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(ProofOfPossessionJwt.TYP))
                .jwk(holder.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(audience).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private String credentialRequest(ECKey holder, String tenant, String nonce) throws Exception {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("credential_configuration_id", CONFIGURATION);
        body.putObject("proofs").putArray("jwt").add(proof(holder, "https://" + tenant + ".issuer.test", nonce));
        return body.toString();
    }

    @Test
    void aCodeOfferedByOneTenantCannotBeRedeemedAtAnother() throws Exception {
        offer("bank", "code-1");
        assertThatThrownBy(() -> token("shop", "code-1")).isInstanceOf(Oid4vciException.class);
        // Still there for the tenant that offered it.
        assertThat(token("bank", "code-1").path("access_token").asText()).isNotEmpty();
    }

    @Test
    void anAccessTokenIsRefusedByEveryOtherTenant() throws Exception {
        offer("bank", "code-2");
        String accessToken = token("bank", "code-2").path("access_token").asText();

        Jwt atBank = decodeAt("bank", accessToken);
        assertThat(atBank.getIssuer().toString()).isEqualTo("https://bank.issuer.test");
        assertThat(atBank.getAudience()).containsExactly("https://bank.issuer.test");
        assertThatThrownBy(() -> decodeAt("shop", accessToken)).isInstanceOf(JwtException.class);
    }

    @Test
    void theClaimsBehindATokenAndANonceAreOnlyKnownToTheirTenant() throws Exception {
        offer("bank", "code-3");
        Jwt token = decodeAt("bank", token("bank", "code-3").path("access_token").asText());
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();

        // A nonce from the bank, used at the shop: refused.
        String bankNonce = nonces.issue(context("bank"));
        assertThatThrownBy(() -> credentialController.credential(token, credentialRequest(holder, "shop", bankNonce), at("shop")))
                .isInstanceOf(Oid4vciException.class);
        // The token's claims are the bank's: the shop has none for it, even with its own nonce.
        String shopNonce = nonces.issue(context("shop"));
        assertThatThrownBy(() -> credentialController.credential(token, credentialRequest(holder, "shop", shopNonce), at("shop")))
                .isInstanceOf(Oid4vciException.class).hasMessageContaining("no claims");

        // At the bank, the credential is the bank's: its identifier and its key.
        var response = credentialController.credential(token, credentialRequest(holder, "bank", nonces.issue(context("bank"))), at("bank"));
        String issued = MAPPER.readTree(response.getBody()).path("credentials").get(0).path("credential").asText();
        SignedJWT issuerJwt = SignedJWT.parse(issued.substring(0, issued.indexOf('~')));
        assertThat(issuerJwt.getJWTClaimsSet().getIssuer()).isEqualTo("https://bank.issuer.test");
        assertThat(issuerJwt.verify(new ECDSAVerifier(keyByTenant.get("bank").toPublicJWK()))).isTrue();
        assertThat(issuerJwt.verify(new ECDSAVerifier(keyByTenant.get("shop").toPublicJWK()))).isFalse();
    }

    @Test
    void eachTenantPublishesOnlyItsOwnKeys() throws Exception {
        JwksController jwks = new JwksController(keys, issuers);
        JsonNode bank = MAPPER.readTree(jwks.jwks(at("bank")).getBody());
        JsonNode shop = MAPPER.readTree(jwks.jwks(at("shop")).getBody());
        assertThat(bank.path("keys").get(0).path("kid").asText()).isEqualTo("bank-1");
        assertThat(shop.path("keys").get(0).path("kid").asText()).isEqualTo("shop-1");
        assertThat(bank.toString()).doesNotContain("\"d\"");
    }

    @Test
    void keysNamingAnotherTenantAreRefusedAtTheDefaultTenant() {
        IssuerContext single = IssuerContext.single("https://issuer.test");
        assertThat(single.scope("abc")).isEqualTo("abc");
        assertThat(new IssuerContext("bank", "https://bank.issuer.test").scope("abc")).isEqualTo("bank|abc");
        // "bank|abc" is the bank's entry: presenting it at the default tenant must not reach it.
        assertThat(single.scopeIfValid("bank|abc")).isEmpty();
        offer("bank", "code-4");
        assertThatThrownBy(() -> codes.redeem(single, new com.darkedges.oid4vci.core.token.PreAuthorizedCodeTokenRequest("bank|code-4", Optional.empty())))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void outsideARequestAMultiTenantDecoderRefusesEveryToken() throws Exception {
        offer("bank", "code-5");
        String accessToken = token("bank", "code-5").path("access_token").asText();
        RequestContextHolder.resetRequestAttributes();
        assertThatThrownBy(() -> new IssuerAccessTokenDecoder(keys, issuers, true).decode(accessToken)).isInstanceOf(JwtException.class);
    }
}
