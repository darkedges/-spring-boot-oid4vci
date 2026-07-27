package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.MsoMdocCredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.core.proof.ProofOfPossessionJwt;
import com.darkedges.oid4vci.core.token.PreAuthorizedCodeTokenRequest;
import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.fasterxml.jackson.databind.JsonNode;
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The full pre-authorized_code issuance pipeline (mint code -&gt; redeem for a token -&gt; fetch a nonce
 * -&gt; build+verify a proof of possession -&gt; issue), driven entirely in-process against real
 * {@code oid4vci-issuer-core} services for both credential formats. This is the first proof that the
 * reuse seam this project is built around actually works: the issued bytes are independently parseable
 * by {@code oid4vp-format-sdjwt-vc}/{@code oid4vp-format-mdoc}'s own {@code HeldCredential.parse}
 * factories, before {@code oid4vci-wallet-core} (which will call those same factories for real) exists.
 */
class IssuancePipelineTest {

    private static final String CREDENTIAL_ISSUER = "https://issuer.example.org";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private record Fixture(
            PreAuthorizedCodeStore codeStore, PreAuthorizedCodeService codeService,
            NonceStore nonceStore, NonceService nonceService,
            AccessTokenService accessTokenService, ProofOfPossessionValidator proofValidator,
            SdJwtVcCredentialIssuanceService sdJwtService, MsoMdocCredentialIssuanceService mdocService,
            ECKey holderKey) {}

    private static Fixture buildFixture() throws Exception {
        ECKey sdJwtIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("sd-jwt-issuer-1").generate();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair mdocIssuerKeyPair = generator.generateKeyPair();

        ECKey holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder-1").generate();

        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        NonceStore nonceStore = new InMemoryNonceStore();
        NonceService nonceService = new NonceService(nonceStore, CLOCK, Duration.ofMinutes(5));

        return new Fixture(
                codeStore,
                new PreAuthorizedCodeService(codeStore, CLOCK),
                nonceStore,
                nonceService,
                new AccessTokenService(sdJwtIssuerKey, CREDENTIAL_ISSUER, Duration.ofMinutes(5), CLOCK),
                new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5)),
                new SdJwtVcCredentialIssuanceService(sdJwtIssuerKey, CREDENTIAL_ISSUER, List.of(), Duration.ofDays(365), CLOCK),
                new MsoMdocCredentialIssuanceService(mdocIssuerKeyPair.getPrivate(), List.of(), Duration.ofDays(365), CLOCK),
                holderKey);
    }

    private static String buildProofJwt(ECKey holderKey, String nonce) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(CREDENTIAL_ISSUER)
                .issueTime(Date.from(NOW))
                .claim("nonce", nonce)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ProofOfPossessionJwt.TYP))
                .jwk(holderKey.toPublicJWK())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) holderKey.toECPrivateKey()));
        return jwt.serialize();
    }

    @Test
    void issuesASdJwtVcCredentialThatIndependentlyParsesAndCarriesTheRightClaims() throws Exception {
        Fixture fixture = buildFixture();
        PreAuthorizedCodeSession session = new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), java.util.Optional.empty(),
                Map.of("given_name", "Jane", "family_name", "Doe"), NOW.plus(Duration.ofMinutes(10)));
        fixture.codeStore().save("code-1", session);

        PreAuthorizedCodeSession redeemed = fixture.codeService().redeem(new PreAuthorizedCodeTokenRequest("code-1", java.util.Optional.empty()));
        AccessTokenService.IssuedAccessToken issuedToken = fixture.accessTokenService().issue(redeemed);
        AccessTokenService.AccessTokenClaims tokenClaims = fixture.accessTokenService().verify(issuedToken.tokenResponse().accessToken());
        assertThat(tokenClaims.credentialConfigurationIds()).containsExactly("UniversityDegreeCredential");
        assertThat(tokenClaims.subject()).isEqualTo(issuedToken.subject());

        String nonce = fixture.nonceService().issue();
        String proofJwt = buildProofJwt(fixture.holderKey(), nonce);
        ECKey provenHolderKey = fixture.proofValidator().verify(proofJwt, CREDENTIAL_ISSUER);
        assertThat(provenHolderKey.getKeyID()).isEqualTo(fixture.holderKey().getKeyID());

        SdJwtVcCredentialConfiguration configuration = new SdJwtVcCredentialConfiguration(
                "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of());
        String issued = fixture.sdJwtService().issue(configuration, redeemed.claims(), provenHolderKey);

        SdJwtVcHeldCredential heldCredential = SdJwtVcHeldCredential.parse(issued);
        JsonNode claims = heldCredential.claimsView();
        assertThat(claims.get("given_name").asText()).isEqualTo("Jane");
        assertThat(claims.get("family_name").asText()).isEqualTo("Doe");
        assertThat(heldCredential.hasCryptographicHolderBinding()).isTrue();
    }

    @Test
    void issuesAnMsoMdocCredentialThatIndependentlyParsesAndCarriesTheRightClaims() throws Exception {
        Fixture fixture = buildFixture();
        PreAuthorizedCodeSession session = new PreAuthorizedCodeSession(
                List.of("org.iso.18013.5.1.mDL"), java.util.Optional.empty(),
                Map.of("given_name", "Jane", "family_name", "Doe"), NOW.plus(Duration.ofMinutes(10)));
        fixture.codeStore().save("code-2", session);

        PreAuthorizedCodeSession redeemed = fixture.codeService().redeem(new PreAuthorizedCodeTokenRequest("code-2", java.util.Optional.empty()));

        String nonce = fixture.nonceService().issue();
        String proofJwt = buildProofJwt(fixture.holderKey(), nonce);
        ECKey provenHolderKey = fixture.proofValidator().verify(proofJwt, CREDENTIAL_ISSUER);

        MsoMdocCredentialConfiguration configuration = new MsoMdocCredentialConfiguration(
                "org.iso.18013.5.1.mDL",
                List.of(new com.darkedges.oid4vci.core.metadata.ClaimDescription(
                                com.darkedges.oid4vp.core.dcql.ClaimsPathPointer.of("org.iso.18013.5.1", "given_name"), java.util.Optional.empty()),
                        new com.darkedges.oid4vci.core.metadata.ClaimDescription(
                                com.darkedges.oid4vp.core.dcql.ClaimsPathPointer.of("org.iso.18013.5.1", "family_name"), java.util.Optional.of(true))),
                Map.of(), List.of(), List.of());

        String issued = fixture.mdocService().issue(configuration, redeemed.claims(), provenHolderKey);

        byte[] issuerSigned = Base64.getUrlDecoder().decode(issued);
        MdocHeldCredential heldCredential = MdocHeldCredential.parse(issuerSigned);
        JsonNode claims = heldCredential.claimsView().get("org.iso.18013.5.1");
        assertThat(claims.get("given_name").asText()).isEqualTo("Jane");
        assertThat(claims.get("family_name").asText()).isEqualTo("Doe");
    }

    @Test
    void redeemingTheSameCodeTwiceFailsTheSecondTime() throws Exception {
        Fixture fixture = buildFixture();
        PreAuthorizedCodeSession session = new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential"), java.util.Optional.empty(), Map.of(), NOW.plus(Duration.ofMinutes(10)));
        fixture.codeStore().save("code-3", session);

        fixture.codeService().redeem(new PreAuthorizedCodeTokenRequest("code-3", java.util.Optional.empty()));

        assertThatThrownBy(() -> fixture.codeService().redeem(new PreAuthorizedCodeTokenRequest("code-3", java.util.Optional.empty())))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void reusingAConsumedNonceInASecondProofFails() throws Exception {
        Fixture fixture = buildFixture();
        String nonce = fixture.nonceService().issue();
        String firstProof = buildProofJwt(fixture.holderKey(), nonce);
        fixture.proofValidator().verify(firstProof, CREDENTIAL_ISSUER);

        String secondProof = buildProofJwt(fixture.holderKey(), nonce);
        assertThatThrownBy(() -> fixture.proofValidator().verify(secondProof, CREDENTIAL_ISSUER))
                .isInstanceOf(Oid4vciException.class);
    }

}
