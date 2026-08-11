package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.dpop.DpopProof;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DpopProofValidatorTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String HTU = "https://issuer.example.org/token";

    @Test
    void acceptsAWellFormedFreshProofAndReturnsItsKey() throws Exception {
        ECKey key = generateKey();
        DpopProofValidator validator = new DpopProofValidator(new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1));

        ECKey returned = validator.verifyForTokenRequest(proof(key, "POST", HTU, NOW, UUID.randomUUID().toString()), "POST", HTU);

        assertThat(returned.getKeyID()).isEqualTo(key.getKeyID());
    }

    @Test
    void rejectsAReplayedJti() throws Exception {
        ECKey key = generateKey();
        DpopProofValidator validator = new DpopProofValidator(new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1));
        String jti = UUID.randomUUID().toString();
        String firstProof = proof(key, "POST", HTU, NOW, jti);
        validator.verifyForTokenRequest(firstProof, "POST", HTU);

        String secondProofSameJti = proof(key, "POST", HTU, NOW, jti);

        assertThatThrownBy(() -> validator.verifyForTokenRequest(secondProofSameJti, "POST", HTU))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAStaleProof() throws Exception {
        ECKey key = generateKey();
        DpopProofValidator validator = new DpopProofValidator(new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1));
        String stale = proof(key, "POST", HTU, NOW.minus(Duration.ofMinutes(10)), UUID.randomUUID().toString());

        assertThatThrownBy(() -> validator.verifyForTokenRequest(stale, "POST", HTU))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void rejectsAProofForADifferentHttpMethod() throws Exception {
        ECKey key = generateKey();
        DpopProofValidator validator = new DpopProofValidator(new InMemoryDpopReplayStore(), CLOCK, Duration.ofMinutes(1));
        String wrongMethod = proof(key, "GET", HTU, NOW, UUID.randomUUID().toString());

        assertThatThrownBy(() -> validator.verifyForTokenRequest(wrongMethod, "POST", HTU))
                .isInstanceOf(Oid4vciException.class);
    }

    @Test
    void computesTheSameThumbprintForTheSameKey() throws Exception {
        ECKey key = generateKey();

        assertThat(DpopProofValidator.computeThumbprint(key)).isEqualTo(DpopProofValidator.computeThumbprint(key));
    }

    private static String proof(ECKey key, String htm, String htu, Instant iat, String jti) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", htm)
                .claim("htu", htu)
                .issueTime(Date.from(iat))
                .jwtID(jti)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(DpopProof.TYP))
                .jwk(key.toPublicJWK())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static ECKey generateKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
    }
}
