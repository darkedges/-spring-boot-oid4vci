package com.darkedges.oid4vci.wallet;

import com.darkedges.oid4vci.core.proof.ProofOfPossessionJwt;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;

/**
 * Builds a {@code jwt}-type proof of possession (OID4VCI 1.0, Section 8.2). Mirrors
 * {@code KbJwtBuilder}'s shape (a static builder using plain custom claims, not Nimbus's registered-claim
 * helpers, so the serialized JSON matches the spec's own examples) but is a genuinely different JWT: a
 * different {@code typ}, the Wallet's public key embedded directly in the JWT *header* (there's no
 * existing {@code cnf} to reference yet — this JWT is what establishes one), and no {@code sd_hash} claim.
 */
public final class ProofJwtBuilder {

    private ProofJwtBuilder() {}

    public static SignedJWT build(String audience, String nonce, Instant iat, ECKey holderKey) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(iat))
                .claim("nonce", nonce)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(ProofOfPossessionJwt.TYP))
                .jwk(holderKey.toPublicJWK())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new ECDSASigner(holderKey));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to sign proof of possession JWT", e);
        }
        return jwt;
    }
}
