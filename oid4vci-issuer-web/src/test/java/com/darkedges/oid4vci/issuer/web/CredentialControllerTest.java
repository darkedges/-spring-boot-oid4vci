package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.BatchCredentialIssuance;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.core.proof.ProofOfPossessionJwt;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.InMemoryIssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.NonceService;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialControllerTest {

    private static final URI CREDENTIAL_ISSUER = URI.create("https://issuer.example.org");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Jwt accessToken(String subject, List<String> configurationIds) {
        return Jwt.withTokenValue("token-value")
                .header("alg", "ES256")
                .claim("sub", subject)
                .claim("credential_configuration_ids", configurationIds)
                .issuedAt(NOW)
                .expiresAt(NOW.plus(Duration.ofMinutes(5)))
                .build();
    }

    private static String proofJwt(ECKey holderKey, String nonce) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(CREDENTIAL_ISSUER.toString())
                .issueTime(Date.from(NOW))
                .claim("nonce", nonce)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ProofOfPossessionJwt.TYP))
                .jwk(holderKey.toPublicJWK())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(CREDENTIAL_ISSUER.getScheme());
        request.setServerName(CREDENTIAL_ISSUER.getHost());
        request.setServerPort(443);
        return request;
    }

    @Test
    void issuesACredentialWhenTheTokenAuthorizesTheRequestedConfiguration() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder-1").generate();

        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));

        NonceService nonceService = new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5));
        ProofOfPossessionValidator proofValidator = new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5));
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        claimsStore.save("subject-1", Map.of("given_name", "Jane"));

        Map<CredentialFormat, CredentialIssuanceService> issuanceServices = Map.of(
                CredentialFormat.DC_SD_JWT, new SdJwtVcCredentialIssuanceService(
                        issuerKey, List.of(), Duration.ofDays(365), CLOCK));

        CredentialController controller = new CredentialController(template, proofValidator, claimsStore, issuanceServices);

        String nonce = nonceService.issue();
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt").add(proofJwt(holderKey, nonce));

        var response = controller.credential(
                accessToken("subject-1", List.of("UniversityDegreeCredential")), body.toString(), request());

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        String issued = MAPPER.readTree(response.getBody()).get("credentials").get(0).get("credential").asText();
        assertThat(SdJwtVcHeldCredential.parse(issued).claimsView().get("given_name").asText()).isEqualTo("Jane");
    }

    @Test
    void rejectsARequestForAConfigurationTheTokenWasNotAuthorizedFor() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));
        NonceService nonceService = new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5));
        ProofOfPossessionValidator proofValidator = new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5));
        CredentialController controller = new CredentialController(
                template, proofValidator, new InMemoryIssuedAccessTokenClaimsStore(),
                Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVcCredentialIssuanceService(
                        issuerKey, List.of(), Duration.ofDays(365), CLOCK)));

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("credential_configuration_id", "UniversityDegreeCredential");

        assertThatThrownBy(() -> controller.credential(
                accessToken("subject-1", List.of("SomeOtherCredential")), body.toString(), request()))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void issuesOneCredentialPerProofWhenBatchIssuanceIsAdvertised() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        ECKey holderKeyA = new ECKeyGenerator(Curve.P_256).keyID("holder-a").generate();
        ECKey holderKeyB = new ECKeyGenerator(Curve.P_256).keyID("holder-b").generate();

        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())),
                Optional.of(new BatchCredentialIssuance(10)));

        NonceService nonceService = new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5));
        ProofOfPossessionValidator proofValidator = new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5));
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        claimsStore.save("subject-1", Map.of("given_name", "Jane"));

        Map<CredentialFormat, CredentialIssuanceService> issuanceServices = Map.of(
                CredentialFormat.DC_SD_JWT, new SdJwtVcCredentialIssuanceService(
                        issuerKey, List.of(), Duration.ofDays(365), CLOCK));

        CredentialController controller = new CredentialController(template, proofValidator, claimsStore, issuanceServices);

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt")
                .add(proofJwt(holderKeyA, nonceService.issue()))
                .add(proofJwt(holderKeyB, nonceService.issue()));

        var response = controller.credential(
                accessToken("subject-1", List.of("UniversityDegreeCredential")), body.toString(), request());

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        JsonNode credentials = MAPPER.readTree(response.getBody()).get("credentials");
        assertThat(credentials).hasSize(2);
        assertThat(SdJwtVcHeldCredential.parse(credentials.get(0).get("credential").asText())
                .claimsView().get("given_name").asText()).isEqualTo("Jane");
        assertThat(SdJwtVcHeldCredential.parse(credentials.get(1).get("credential").asText())
                .claimsView().get("given_name").asText()).isEqualTo("Jane");
    }

    @Test
    void rejectsMoreProofsThanTheAdvertisedBatchSize() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();

        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())),
                Optional.of(new BatchCredentialIssuance(2)));

        NonceService nonceService = new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5));
        ProofOfPossessionValidator proofValidator = new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5));
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        claimsStore.save("subject-1", Map.of("given_name", "Jane"));

        CredentialController controller = new CredentialController(
                template, proofValidator, claimsStore,
                Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVcCredentialIssuanceService(
                        issuerKey, List.of(), Duration.ofDays(365), CLOCK)));

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt")
                .add(proofJwt(new ECKeyGenerator(Curve.P_256).generate(), nonceService.issue()))
                .add(proofJwt(new ECKeyGenerator(Curve.P_256).generate(), nonceService.issue()))
                .add(proofJwt(new ECKeyGenerator(Curve.P_256).generate(), nonceService.issue()));

        assertThatThrownBy(() -> controller.credential(
                accessToken("subject-1", List.of("UniversityDegreeCredential")), body.toString(), request()))
                .isInstanceOf(Oid4vciException.class)
                .extracting(e -> ((Oid4vciException) e).errorCode())
                .isEqualTo(Oid4vciErrorCode.INVALID_CREDENTIAL_REQUEST);
    }

    @Test
    void rejectsMoreThanOneProofWhenBatchIssuanceIsNotAdvertised() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();

        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));

        NonceService nonceService = new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5));
        ProofOfPossessionValidator proofValidator = new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5));
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        claimsStore.save("subject-1", Map.of("given_name", "Jane"));

        CredentialController controller = new CredentialController(
                template, proofValidator, claimsStore,
                Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVcCredentialIssuanceService(
                        issuerKey, List.of(), Duration.ofDays(365), CLOCK)));

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt")
                .add(proofJwt(new ECKeyGenerator(Curve.P_256).generate(), nonceService.issue()))
                .add(proofJwt(new ECKeyGenerator(Curve.P_256).generate(), nonceService.issue()));

        assertThatThrownBy(() -> controller.credential(
                accessToken("subject-1", List.of("UniversityDegreeCredential")), body.toString(), request()))
                .isInstanceOf(Oid4vciException.class)
                .extracting(e -> ((Oid4vciException) e).errorCode())
                .isEqualTo(Oid4vciErrorCode.INVALID_CREDENTIAL_REQUEST);
    }
}
