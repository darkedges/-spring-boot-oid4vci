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
 */
public final class AccessTokenService {

    private static final String CREDENTIAL_CONFIGURATION_IDS_CLAIM = "credential_configuration_ids";

    private final ECKey issuerKey;
    private final Duration ttl;
    private final Clock clock;

    public AccessTokenService(ECKey issuerKey, Duration ttl, Clock clock) {
        this.issuerKey = issuerKey;
        this.ttl = ttl;
        this.clock = clock;
    }

    /**
     * Mints a token and returns it alongside the fresh {@code subject} identifier embedded in it.
     * {@link PreAuthorizedCodeSession#claims()} is deliberately NOT embedded in the token itself (that
     * would bloat/leak claim data into a bearer credential that may be logged, cached, or otherwise
     * handled less carefully than the credential it's only meant to authorize issuing) — the caller
     * (the real Credential Endpoint's web layer) is expected to separately persist
     * {@code session.claims()} keyed by the returned {@code subject}, e.g. via
     * {@link IssuedAccessTokenClaimsStore}, and look them up again once the token comes back on a
     * Credential Request.
     *
     * @param issuerBaseUrl the Issuer's own base URL as the client that requested this token actually
     *                      reached it (see {@code RequestBaseUrl} in {@code oid4vci-issuer-web}) —
     *                      embedded as this token's {@code iss} claim.
     */
    public IssuedAccessToken issue(PreAuthorizedCodeSession session, String issuerBaseUrl) {
        return issue(session, Optional.empty(), issuerBaseUrl);
    }

    /** As {@link #issue(PreAuthorizedCodeSession, String)}, but when {@code dpopJkt} is present,
     * sender-constrains the minted token to that DPoP proof key by embedding a {@code cnf.jkt} claim
     * (RFC 9449 Section 6) — the Credential Endpoint then requires a matching DPoP proof on every request
     * that presents this token (see {@code DpopProofValidator#verifyForResourceRequest}). */
    public IssuedAccessToken issue(PreAuthorizedCodeSession session, Optional<String> dpopJkt, String issuerBaseUrl) {
        Instant now = clock.instant();
        String subject = UUID.randomUUID().toString();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuerBaseUrl)
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

    /** @throws Oid4vciException with {@link Oid4vciErrorCode#INVALID_TOKEN} if the token's signature is
     * invalid or it has expired. */
    public AccessTokenClaims verify(String accessToken) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(accessToken);
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token is not a well-formed JWT", e);
        }

        try {
            if (!jwt.verify(new ECDSAVerifier(issuerKey.toPublicJWK()))) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token signature verification failed");
            }
        } catch (JOSEException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "access token signature verification failed", e);
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

    public record AccessTokenClaims(String subject, List<String> credentialConfigurationIds) {}

    /**
     * {@code expiresAt} is carried out so callers can bound anything they key on {@code subject}.
     *
     * The claim values held against a subject are useless the moment the token naming it expires,
     * and for an issuer minting real identity credentials they are passport data -- so the store
     * that holds them needs the same instant the JWT was signed with, not an approximation of it.
     */
    public record IssuedAccessToken(TokenResponse tokenResponse, String subject, Instant expiresAt) {}
}
