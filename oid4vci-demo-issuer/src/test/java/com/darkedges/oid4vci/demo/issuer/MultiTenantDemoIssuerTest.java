package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The demo issuer on the "tenancy" profile, over real HTTP: two path tenants and the default tenant, each issuing as itself, and
 * none accepting what another issued. Proofing starts and collects at a tenant, while the proofing service calls one endpoint.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"demo.proofing.callback-secret=test-callback-secret"})
@ActiveProfiles("tenancy")
class MultiTenantDemoIssuerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    @Autowired
    TenantRepository tenants;

    @Autowired
    com.nimbusds.jose.jwk.ECKey applicationSigningKey;

    @BeforeEach
    void tenants() {
        if (tenants.findBySlug("bank").isEmpty()) tenants.save(Tenant.create("env-bank", "org-1", "bank"));
        if (tenants.findBySlug("shop").isEmpty()) tenants.save(Tenant.create("env-shop", "org-2", "shop"));
    }

    private String origin() {
        return "http://localhost:" + port;
    }

    private HttpResponse<String> get(String path) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(origin() + path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String contentType, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(origin() + path)).POST(HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) builder.header("Content-Type", contentType);
        headers.forEach(builder::header);
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String form(Map<String, String> fields) {
        return fields.entrySet().stream().map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private JsonNode json(HttpResponse<String> response) throws Exception {
        return MAPPER.readTree(response.body());
    }

    /** The demo offer at a tenant: its pre-authorized code. */
    private String offeredCode(String prefix) throws Exception {
        JsonNode offer = json(get(prefix + "/demo/offer"));
        assertThat(offer.path("credential_issuer").asText()).isEqualTo(origin() + prefix);
        return offer.path("grants").path("urn:ietf:params:oauth:grant-type:pre-authorized_code").path("pre-authorized_code").asText();
    }

    private HttpResponse<String> token(String prefix, String code) throws Exception {
        return post(prefix + "/token", "application/x-www-form-urlencoded",
                form(Map.of("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code", code)), Map.of());
    }

    private HttpResponse<String> credential(String prefix, String accessToken) throws Exception {
        String nonce = json(post(prefix + "/nonce", null, "", Map.of())).path("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(origin() + prefix).issueTime(new Date()).claim("nonce", nonce).build());
        proof.sign(new ECDSASigner(holder));
        ObjectNode body = MAPPER.createObjectNode().put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt").add(proof.serialize());
        return post(prefix + "/credential", "application/json", body.toString(), Map.of("Authorization", "Bearer " + accessToken));
    }

    @Test
    void eachTenantIssuesAsItselfAndRefusesWhatAnotherIssued() throws Exception {
        // The bank's code: refused by the shop, accepted by the bank.
        String code = offeredCode("/t/bank");
        assertThat(token("/t/shop", code).statusCode()).isEqualTo(400);
        HttpResponse<String> tokenResponse = token("/t/bank", code);
        assertThat(tokenResponse.statusCode()).isEqualTo(200);
        String accessToken = json(tokenResponse).path("access_token").asText();

        // The bank's access token: refused at the shop's Credential Endpoint.
        assertThat(credential("/t/shop", accessToken).statusCode()).isEqualTo(401);
        HttpResponse<String> issued = credential("/t/bank", accessToken);
        assertThat(issued.statusCode()).isEqualTo(200);

        // The credential is the bank's: its identifier, and its key as published at its JWKS.
        String sdJwt = json(issued).path("credentials").get(0).path("credential").asText();
        SignedJWT issuerJwt = SignedJWT.parse(sdJwt.substring(0, sdJwt.indexOf('~')));
        assertThat(issuerJwt.getJWTClaimsSet().getIssuer()).isEqualTo(origin() + "/t/bank");
        ECKey bankKey = JWKSet.parse(get("/t/bank/jwks").body()).getKeys().get(0).toECKey();
        ECKey shopKey = JWKSet.parse(get("/t/shop/jwks").body()).getKeys().get(0).toECKey();
        assertThat(issuerJwt.verify(new ECDSAVerifier(bankKey))).isTrue();
        assertThat(issuerJwt.verify(new ECDSAVerifier(shopKey))).isFalse();
    }

    @Test
    void eachTenantPublishesItsMetadataAtTheInsertedWellKnownUrl() throws Exception {
        JsonNode shop = json(get("/.well-known/openid-credential-issuer/t/shop"));
        assertThat(shop.path("credential_issuer").asText()).isEqualTo(origin() + "/t/shop");
        assertThat(shop.path("credential_endpoint").asText()).isEqualTo(origin() + "/t/shop/credential");
        JsonNode as = json(get("/.well-known/oauth-authorization-server/t/shop"));
        assertThat(as.path("issuer").asText()).isEqualTo(origin() + "/t/shop");
        assertThat(as.path("token_endpoint").asText()).isEqualTo(origin() + "/t/shop/token");
        assertThat(get("/t/nobody/token").statusCode()).isEqualTo(404);
    }

    @Test
    void theDefaultTenantIsTheIssuerAsItWasWithTheApplicationsKeys() throws Exception {
        JsonNode metadata = json(get("/.well-known/openid-credential-issuer"));
        assertThat(metadata.path("credential_issuer").asText()).isEqualTo(origin());
        assertThat(JWKSet.parse(get("/jwks").body()).getKeys().get(0).getKeyID()).isEqualTo(applicationSigningKey.getKeyID());
        assertThat(JWKSet.parse(get("/t/bank/jwks").body()).getKeys().get(0).getKeyID()).isNotEqualTo(applicationSigningKey.getKeyID());

        String code = offeredCode("");
        assertThat(token("/t/bank", code).statusCode()).isEqualTo(400);
        assertThat(token("", code).statusCode()).isEqualTo(200);
    }

    @Test
    void proofingStartsAndIsCollectedAtATenantWhileTheProofingServiceCallsOnePlatformEndpoint() throws Exception {
        JsonNode started = json(post("/t/shop/proofing/session", null, "", Map.of()));
        String sessionId = started.path("session_id").asText();
        String secret = started.path("retrieval_secret").asText();

        ObjectNode result = MAPPER.createObjectNode()
                .put("session_id", sessionId).put("given_names", "ALEXANDRA JANE").put("surname", "FITZGERALD")
                .put("date_of_birth", "870314").put("document_number", "PA1234567").put("nationality", "GBR")
                .put("issuing_state", "GBR").put("date_of_expiry", "310612");
        for (String check : new String[]{"liveness_passed", "face_matched", "sod_signature_valid", "data_group_hashes_valid",
                "csca_validated", "revocation_checked", "portrait_from_chip", "active_authentication_valid"}) result.put(check, true);
        HttpResponse<String> callback = post("/proofing/result", "application/json", result.toString(),
                Map.of("X-Proofing-Secret", "test-callback-secret"));
        assertThat(callback.statusCode()).as(callback.body()).isEqualTo(200);

        // Another tenant can't collect it, even with the secret.
        assertThat(get("/t/bank/proofing/session/" + sessionId + "?secret=" + secret).statusCode()).isEqualTo(404);
        JsonNode collected = json(get("/t/shop/proofing/session/" + sessionId + "?secret=" + secret));
        assertThat(collected.path("status").asText()).isEqualTo("ready");
        JsonNode offer = collected.path("credential_offer");
        assertThat(offer.path("credential_issuer").asText()).isEqualTo(origin() + "/t/shop");
        String code = offer.path("grants").path("urn:ietf:params:oauth:grant-type:pre-authorized_code").path("pre-authorized_code").asText();
        assertThat(token("/t/bank", code).statusCode()).isEqualTo(400);
        assertThat(token("/t/shop", code).statusCode()).isEqualTo(200);
    }
}
