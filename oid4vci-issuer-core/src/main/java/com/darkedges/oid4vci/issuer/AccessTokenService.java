package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.token.TokenResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Mints and verifies the Issuer's own self-signed ES256 access tokens (plain Nimbus {@code SignedJWT}/
 * {@code ECDSASigner}, consistent with this project's "Nimbus directly" convention rather than a Spring
 * {@code JwtEncoder} abstraction). Minting is business logic (the Issuer is its own tiny Authorization
 * Server for the pre-authorized_code grant); {@link #verify} exists for this module's own in-process
 * tests and any non-Spring consumer — the real Credential Endpoint (Phase 5+) verifies via Spring
 * Security's built-in {@code oauth2ResourceServer()}/{@code JwtDecoder} instead, per the project README.
 *
 * <p>Each token is signed with its tenant's key and names its issuer twice, as {@code iss} and {@code aud}: a token issued by one
 * tenant is refused by every other, whose keys and identifier differ.
 */
public final class AccessTokenService {

    private static final String CREDENTIAL_CONFIGURATION_IDS_CLAIM = "credential_configuration_ids";

    private final IssuerKeys keys;
    private final Duration ttl;
    private final Clock clock;

    public AccessTokenService(IssuerKeys keys, Duration ttl, Clock clock) {
        this.keys = keys;
        this.ttl = ttl;
        this.clock = clock;
    }

    /** A single-tenant issuer signing with one key. */
    public AccessTokenService(ECKey issuerKey, Duration ttl, Clock clock) {
        this(IssuerKeys.fixed(issuerKey, null), ttl, clock);
    }

    public IssuedAccessToken issue(PreAuthorizedCodeSession session, String issuerBaseUrl) {
        return issue(IssuerContext.single(issuerBaseUrl), session, Optional.empty());
    }

    public IssuedAccessToken issue(PreAuthorizedCodeSession session, Optional<String> dpopJkt, String issuerBaseUrl) {
        return issue(IssuerContext.single(issuerBaseUrl), session, dpopJkt);
    }

    public IssuedAccessToken issue(IssuerContext context, PreAuthorizedCodeSession session, Optional<String> dpopJkt) {
        ECKey issuerKey = keys.signingKey(context);
        Instant now = clock.instant();
        String subject = UUID.randomUUID().toString();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(context.issuerIdentifier())
                .audience(context.issuerIdentifier())
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .jwtID(UUID.randomUUID().toString())
                .claim(CREDENTIAL_CONFIGURATION_IDS_CLAIM, session.credentialConfigurationIds());
        dpopJkt.ifPresent(jkt -> claimsBuilder.claim("cnf", Map.of("jkt", jkt)));
        JWTClaimsSet claims = claimsBuilder.build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuerKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new ECDSASigner(issuerKey));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to sign access token", e);
        }

        String tokenType = dpopJkt.isPresent() ? "DPoP" : "Bearer";
        TokenResponse response = new TokenResponse(jwt.serialize(), tokenType, Optional.of(ttl.toSeconds()), Optional.empty());
        return new IssuedAccessToken(response, subject, now.plus(ttl));
    }

    /** Verifies the signature and expiry only, for a single-tenant issuer. */
    public AccessTokenClaims verify(String accessToken) {
        return verify(accessToken, keys.verificationKeys(IssuerContext.single("")), null);
    }

    /** Verifies the token was issued by this tenant, on this identifier: its keys, and {@code iss} and {@code aud}. */
    public AccessTokenClaims verify(IssuerContext context, String accessToken) {
        return verify(accessToken, keys.verificationKeys(context), context.issuerIdentifier());
    }

    private AccessTokenClaims verify(String accessToken, List<ECKey> verificationKeys, String expectedIssuer) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(accessToken);
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token is not a well-formed JWT", e);
        }
        if (!JWSAlgorithm.ES256.equals(jwt.getHeader().getAlgorithm()) || !verifiesWithAny(jwt, verificationKeys)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token signature verification failed");
        }
        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token claims could not be parsed", e);
        }
        if (claims.getExpirationTime() == null || claims.getExpirationTime().toInstant().isBefore(clock.instant())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token has expired");
        }
        if (expectedIssuer != null && (!expectedIssuer.equals(claims.getIssuer())
                || claims.getAudience() == null || !claims.getAudience().contains(expectedIssuer))) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token was not issued by this issuer");
        }
        List<String> configurationIds = new ArrayList<>();
        try {
            List<Object> raw = claims.getListClaim(CREDENTIAL_CONFIGURATION_IDS_CLAIM);
            if (raw != null) {
                raw.forEach(v -> configurationIds.add(String.valueOf(v)));
            }
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token credential_configuration_ids claim is malformed", e);
        }
        return new AccessTokenClaims(claims.getSubject(), List.copyOf(configurationIds));
    }

    private static boolean verifiesWithAny(SignedJWT jwt, List<ECKey> verificationKeys) {
        String kid = jwt.getHeader().getKeyID();
        for (ECKey key : verificationKeys) {
            if (kid != null && key.getKeyID() != null && !kid.equals(key.getKeyID())) continue;
            try {
                if (jwt.verify(new ECDSAVerifier(key.toPublicJWK()))) return true;
            } catch (JOSEException e) {
                // try the next key
            }
        }
        return false;
    }

    public record AccessTokenClaims(String subject, List<String> credentialConfigurationIds) {}

    public record IssuedAccessToken(TokenResponse tokenResponse, String subject, Instant expiresAt) {}
}
