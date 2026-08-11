package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.dpop.DpopProof;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
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
 * Validates a DPoP proof JWT (RFC 9449) presented at the Token Endpoint: the JWT's signature against the
 * public key embedded in its own {@code jwk} header (same self-asserted-key posture as
 * {@link ProofOfPossessionValidator} — this is proof of *possession* of the key, not of the key's
 * identity), {@code typ}, {@code htm}/{@code htu} against the request actually being made, {@code iat}
 * freshness, and single-use {@code jti} via a {@link DpopReplayStore}. No server-provided DPoP nonce
 * (RFC 9449 Section 8) is implemented — this issuer relies on {@code iat} freshness plus replay tracking,
 * same trust model {@code NonceService}'s short TTL already uses elsewhere in this project.
 *
 * <p>This only covers the Token Endpoint (Authorization Server) side — minting a token bound to the
 * verified key's thumbprint ({@code cnf.jkt}, see {@code AccessTokenService#issue}). Verifying a DPoP
 * proof presented back at the Credential Endpoint (Resource Server side, including the {@code ath} check
 * against the presented access token) is instead handled by Spring Security 7.1's own native
 * {@code .dPoP(...)} resource-server support — confirmed live that a hand-rolled equivalent here was
 * unreachable, since {@code BearerTokenAuthenticationFilter} already refuses a {@code cnf}-bearing JWT
 * unless it was authenticated via that native DPoP path.
 */
public final class DpopProofValidator {

    private final DpopReplayStore replayStore;
    private final Clock clock;
    private final Duration allowedClockSkew;

    public DpopProofValidator(DpopReplayStore replayStore, Clock clock, Duration allowedClockSkew) {
        this.replayStore = replayStore;
        this.clock = clock;
        this.allowedClockSkew = allowedClockSkew;
    }

    /** Validates a DPoP proof presented at the Token Endpoint and returns its public key, so its JWK
     * thumbprint can be bound into the freshly minted access token's {@code cnf.jkt} claim. */
    public ECKey verifyForTokenRequest(String proofJwt, String httpMethod, String httpUri) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(proofJwt);
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof is not a well-formed JWT", e);
        }

        if (jwt.getHeader().getType() == null || !DpopProof.TYP.equals(jwt.getHeader().getType().getType())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF,
                    "DPoP proof \"typ\" header must be \"" + DpopProof.TYP + "\"");
        }

        JWK jwk = jwt.getHeader().getJWK();
        if (!(jwk instanceof ECKey proofKey)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof header must carry an EC \"jwk\"");
        }

        try {
            if (!jwt.verify(new ECDSAVerifier(proofKey))) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof signature verification failed");
            }
        } catch (JOSEException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof signature verification failed", e);
        }

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof claims could not be parsed", e);
        }

        String htm = getStringClaim(claims, "htm");
        if (!httpMethod.equalsIgnoreCase(htm)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof \"htm\" does not match the request method");
        }

        String htu = getStringClaim(claims, "htu");
        if (!httpUri.equals(htu)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof \"htu\" does not match the request URL");
        }

        if (claims.getIssueTime() == null) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof is missing required \"iat\" claim");
        }
        Instant iat = claims.getIssueTime().toInstant();
        Instant now = clock.instant();
        if (iat.isAfter(now.plus(allowedClockSkew)) || iat.isBefore(now.minus(allowedClockSkew))) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof \"iat\" is not fresh: " + iat);
        }

        String jti = getStringClaim(claims, "jti");
        if (jti == null || jti.isBlank()) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof is missing required \"jti\" claim");
        }
        if (!replayStore.recordUse(jti, now, now.plus(allowedClockSkew.multipliedBy(2)))) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof \"jti\" has already been used");
        }

        return proofKey;
    }

    /** RFC 7638 JWK thumbprint (SHA-256, base64url), bound into a freshly minted access token's
     * {@code cnf.jkt} claim so Spring Security's resource-server DPoP support can later match it against
     * a proof's key. */
    public static String computeThumbprint(ECKey key) {
        try {
            return key.computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to compute JWK thumbprint", e);
        }
    }

    private static String getStringClaim(JWTClaimsSet claims, String name) {
        try {
            return claims.getStringClaim(name);
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_DPOP_PROOF, "DPoP proof \"" + name + "\" claim is not a string", e);
        }
    }
}
