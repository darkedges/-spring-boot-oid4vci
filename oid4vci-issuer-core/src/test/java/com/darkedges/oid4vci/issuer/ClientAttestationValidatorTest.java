package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.error.AttestationChallengeRequiredException;
import com.darkedges.oid4vci.core.error.Oid4vciException;
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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientAttestationValidatorTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String TRUSTED_ISSUER = "https://wallet-provider.example.org";
    private static final String ISSUER_IDENTIFIER = "https://issuer.example.org";
    private static final String CLIENT_ID = "wallet-instance-1";

    @Test
    void acceptsAWellFormedAttestationAndPopAndReturnsTheClientId() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        ClientAttestationValidator validator = validator(walletProviderKey);

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        String pop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString());

        String clientId = validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER);

        assertThat(clientId).isEqualTo(CLIENT_ID);
    }

    @Test
    void rejectsAnAttestationNotSignedByTheTrustedWalletProvider() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey impostorKey = generateKey("impostor");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        ClientAttestationValidator validator = validator(walletProviderKey);

        String attestation = attestationJwt(impostorKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        String pop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString());

        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAnExpiredAttestation() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        ClientAttestationValidator validator = validator(walletProviderKey);

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.minus(Duration.ofMinutes(1)));
        String pop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString());

        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAPopNotSignedByTheAttestedWalletInstanceKey() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        ECKey wrongKey = generateKey("wrong-key");
        ClientAttestationValidator validator = validator(walletProviderKey);

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        String pop = popJwt(wrongKey, NOW, UUID.randomUUID().toString());

        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAPopWhoseAudienceIsNotThisIssuersIdentifier() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        ClientAttestationValidator validator = validator(walletProviderKey);

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        String pop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString(), "https://other-issuer.example.org");

        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAReplayedPopJti() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        ClientAttestationValidator validator = validator(walletProviderKey);
        String jti = UUID.randomUUID().toString();

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        validator.verifyForTokenRequest(attestation, popJwt(walletInstanceKey, NOW, jti), ISSUER_IDENTIFIER);

        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, popJwt(walletInstanceKey, NOW, jti), ISSUER_IDENTIFIER))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void acceptsAPopCarryingAValidChallengeWhenChallengeEndpointIsConfigured() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        AttestationChallengeService challengeService = new AttestationChallengeService(
                new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5)));
        ClientAttestationValidator validator = validator(walletProviderKey, Optional.of(challengeService));

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        String challenge = challengeService.issue();
        String pop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString(), ISSUER_IDENTIFIER, Optional.of(challenge));

        String clientId = validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER);

        assertThat(clientId).isEqualTo(CLIENT_ID);
    }

    @Test
    void rejectsAPopMissingTheChallengeClaimWhenChallengeEndpointIsConfigured() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        AttestationChallengeService challengeService = new AttestationChallengeService(
                new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5)));
        ClientAttestationValidator validator = validator(walletProviderKey, Optional.of(challengeService));

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        String pop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString());

        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, pop, ISSUER_IDENTIFIER))
                .isInstanceOf(AttestationChallengeRequiredException.class)
                .extracting(e -> ((AttestationChallengeRequiredException) e).challenge())
                .isNotNull();
    }

    @Test
    void rejectsAPopWithAnAlreadyConsumedChallenge() throws Exception {
        ECKey walletProviderKey = generateKey("wallet-provider-1");
        ECKey walletInstanceKey = generateKey("wallet-instance-1");
        AttestationChallengeService challengeService = new AttestationChallengeService(
                new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5)));
        ClientAttestationValidator validator = validator(walletProviderKey, Optional.of(challengeService));
        String challenge = challengeService.issue();

        String attestation = attestationJwt(walletProviderKey, walletInstanceKey, NOW.plus(Duration.ofMinutes(10)));
        validator.verifyForTokenRequest(attestation,
                popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString(), ISSUER_IDENTIFIER, Optional.of(challenge)),
                ISSUER_IDENTIFIER);

        String replayedPop = popJwt(walletInstanceKey, NOW, UUID.randomUUID().toString(), ISSUER_IDENTIFIER, Optional.of(challenge));
        assertThatThrownBy(() -> validator.verifyForTokenRequest(attestation, replayedPop, ISSUER_IDENTIFIER))
                .isInstanceOf(AttestationChallengeRequiredException.class);
    }

    private static ClientAttestationValidator validator(ECKey trustedWalletProviderKey) {
        return validator(trustedWalletProviderKey, Optional.empty());
    }

    private static ClientAttestationValidator validator(
            ECKey trustedWalletProviderKey, Optional<AttestationChallengeService> challengeService) {
        return new ClientAttestationValidator(
                new ClientAttestationTrustAnchor(TRUSTED_ISSUER, trustedWalletProviderKey.toPublicJWK()),
                new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1), challengeService);
    }

    private static String attestationJwt(ECKey signingKey, ECKey walletInstanceKey, Instant expiry) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(TRUSTED_ISSUER)
                .subject(CLIENT_ID)
                .expirationTime(Date.from(expiry))
                .claim("cnf", Map.of("jwk", walletInstanceKey.toPublicJWK().toJSONObject()))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ClientAttestation.ATTESTATION_TYP))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private static String popJwt(ECKey signingKey, Instant iat, String jti) throws Exception {
        return popJwt(signingKey, iat, jti, ISSUER_IDENTIFIER);
    }

    private static String popJwt(ECKey signingKey, Instant iat, String jti, String audience) throws Exception {
        return popJwt(signingKey, iat, jti, audience, Optional.empty());
    }

    private static String popJwt(
            ECKey signingKey, Instant iat, String jti, String audience, Optional<String> challenge) throws Exception {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(CLIENT_ID)
                .audience(audience)
                .issueTime(Date.from(iat))
                .jwtID(jti);
        challenge.ifPresent(c -> claimsBuilder.claim(ClientAttestation.CHALLENGE_CLAIM_NAME, c));
        JWTClaimsSet claims = claimsBuilder.build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ClientAttestation.ATTESTATION_POP_TYP))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private static ECKey generateKey(String keyId) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
    }
}
