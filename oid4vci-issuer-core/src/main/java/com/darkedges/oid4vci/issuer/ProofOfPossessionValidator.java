package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.proof.ProofOfPossessionJwt;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Verifies a {@code jwt}-type proof of possession (OID4VCI 1.0, Section 8.2/Appendix F.1): the JWT's
 * signature against the public key embedded in its own header (self-asserted — proof of *possession*,
 * not of *trust*; nothing here vouches for the key's identity, this is the Wallet's first assertion of
 * this key, there's nothing else yet to check it against), that {@code aud} matches the Credential
 * Issuer and {@code nonce} matches an issued-and-unconsumed {@code c_nonce}, and that {@code iat} is
 * fresh. Returns the validated public key so the caller can bind it into the new credential's
 * {@code cnf}/{@code deviceKey}.
 */
public final class ProofOfPossessionValidator {

    private final NonceService nonceService;
    private final Clock clock;
    private final Duration allowedClockSkew;

    public ProofOfPossessionValidator(NonceService nonceService, Clock clock, Duration allowedClockSkew) {
        this.nonceService = nonceService;
        this.clock = clock;
        this.allowedClockSkew = allowedClockSkew;
    }

    public ECKey verify(String proofJwt, String expectedAudience) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(proofJwt);
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof is not a well-formed JWT", e);
        }

        if (jwt.getHeader().getType() == null || !ProofOfPossessionJwt.TYP.equals(jwt.getHeader().getType().getType())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF,
                    "proof JWT \"typ\" header must be \"" + ProofOfPossessionJwt.TYP + "\"");
        }

        JWK jwk = jwt.getHeader().getJWK();
        if (!(jwk instanceof ECKey holderKey)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT header must carry an EC \"jwk\"");
        }

        try {
            if (!jwt.verify(new ECDSAVerifier(holderKey))) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT signature verification failed");
            }
        } catch (JOSEException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT signature verification failed", e);
        }

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT claims could not be parsed", e);
        }

        if (claims.getAudience() == null || !claims.getAudience().contains(expectedAudience)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF,
                    "proof JWT \"aud\" does not match the Credential Issuer");
        }

        String nonce;
        try {
            nonce = claims.getStringClaim("nonce");
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT \"nonce\" claim is not a string", e);
        }
        if (nonce == null) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT is missing required \"nonce\" claim");
        }
        nonceService.requireValid(nonce);

        if (claims.getIssueTime() == null) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT is missing required \"iat\" claim");
        }
        Instant iat = claims.getIssueTime().toInstant();
        Instant now = clock.instant();
        if (iat.isAfter(now.plus(allowedClockSkew)) || iat.isBefore(now.minus(allowedClockSkew))) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proof JWT \"iat\" is not fresh: " + iat);
        }

        return holderKey;
    }
}
