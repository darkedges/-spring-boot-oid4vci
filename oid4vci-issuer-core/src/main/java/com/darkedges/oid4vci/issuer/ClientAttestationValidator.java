package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.error.AttestationChallengeRequiredException;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Verifies a Wallet's OAuth 2.0 Attestation-Based Client Authentication ({@code attest_jwt_client_auth},
 * draft-ietf-oauth-attestation-based-client-auth) at the Token Endpoint — see {@link ClientAttestation}.
 * The Client Attestation JWT must be signed by the configured {@link ClientAttestationTrustAnchor}'s
 * Wallet Provider key and carry a {@code cnf.jwk} for the Wallet instance; the Client Attestation PoP JWT
 * must then be signed by <em>that</em> key and bound to this specific token request ({@code aud} = the
 * Authorization Server's own {@code issuer} identifier — <strong>not</strong> the Token Endpoint URL, per
 * draft-ietf-oauth-attestation-based-client-auth Section 5.2 and confirmed against the OpenID Conformance
 * Suite's own {@code CreateClientAttestationProofJwt}, which sets {@code aud} to
 * {@code server.issuer} — {@code iss} = the attested client id, fresh {@code iat}, single-use
 * {@code jti}) — the same possession-proof shape DPoP already uses elsewhere in this issuer (see
 * {@code DpopProofValidator}), just proving possession of the Wallet's client identity rather than
 * sender-constraining a token. {@code popReplayStore} is a separate store from DPoP's own — same
 * {@link DpopReplayStore} interface (it's generic single-use-jti bookkeeping, not DPoP-specific), but a
 * distinct instance since the two jti namespaces must never collide.
 */
public final class ClientAttestationValidator {

    private final ClientAttestationTrustAnchor trustAnchor;
    private final DpopReplayStore popReplayStore;
    private final Clock clock;
    private final Duration allowedClockSkew;
    private final Optional<AttestationChallengeService> challengeService;

    /** As the canonical constructor, but with no Challenge Endpoint requirement (see
     * {@link AttestationChallengeService}) — for the many existing call sites (tests, apps that don't
     * enable {@code oid4vci.issuer.attestation-challenge-endpoint-path}) that don't need one. */
    public ClientAttestationValidator(
            ClientAttestationTrustAnchor trustAnchor, DpopReplayStore popReplayStore, Clock clock, Duration allowedClockSkew) {
        this(trustAnchor, popReplayStore, clock, allowedClockSkew, Optional.empty());
    }

    public ClientAttestationValidator(
            ClientAttestationTrustAnchor trustAnchor, DpopReplayStore popReplayStore, Clock clock, Duration allowedClockSkew,
            Optional<AttestationChallengeService> challengeService) {
        this.trustAnchor = trustAnchor;
        this.popReplayStore = popReplayStore;
        this.clock = clock;
        this.allowedClockSkew = allowedClockSkew;
        this.challengeService = challengeService;
    }

    /**
     * @param issuerIdentifier this Authorization Server's own {@code issuer} identifier (the AS metadata
     *                         document's {@code issuer} field — see {@code RequestBaseUrl}), which the
     *                         Client Attestation PoP JWT's {@code aud} must match.
     * @return the authenticated client id (the Client Attestation JWT's {@code sub}).
     */
    public String verifyForTokenRequest(String attestationJwt, String popJwt, String issuerIdentifier) {
        SignedJWT attestation = parse(attestationJwt, "Client Attestation");
        requireType(attestation, ClientAttestation.ATTESTATION_TYP, "Client Attestation");
        verifySignature(attestation, trustAnchor.trustedIssuerKey(), "Client Attestation");
        JWTClaimsSet attestationClaims = claims(attestation, "Client Attestation");

        if (!trustAnchor.trustedIssuer().equals(attestationClaims.getIssuer())) {
            throw invalidClient("Client Attestation \"iss\" is not a trusted Wallet Provider: " + attestationClaims.getIssuer());
        }
        String clientId = attestationClaims.getSubject();
        if (clientId == null || clientId.isBlank()) {
            throw invalidClient("Client Attestation is missing required \"sub\" claim");
        }
        Instant now = clock.instant();
        if (attestationClaims.getExpirationTime() == null || attestationClaims.getExpirationTime().toInstant().isBefore(now)) {
            throw invalidClient("Client Attestation has expired");
        }
        ECKey walletInstanceKey = readConfirmationKey(attestationClaims);

        SignedJWT pop = parse(popJwt, "Client Attestation PoP");
        requireType(pop, ClientAttestation.ATTESTATION_POP_TYP, "Client Attestation PoP");
        verifySignature(pop, walletInstanceKey, "Client Attestation PoP");
        JWTClaimsSet popClaims = claims(pop, "Client Attestation PoP");

        if (!clientId.equals(popClaims.getIssuer())) {
            throw invalidClient("Client Attestation PoP \"iss\" does not match the attested client id");
        }
        List<String> audience = popClaims.getAudience();
        if (audience == null || !audience.contains(issuerIdentifier)) {
            throw invalidClient("Client Attestation PoP \"aud\" does not match the authorization server issuer identifier");
        }
        if (popClaims.getIssueTime() == null) {
            throw invalidClient("Client Attestation PoP is missing required \"iat\" claim");
        }
        Instant iat = popClaims.getIssueTime().toInstant();
        if (iat.isAfter(now.plus(allowedClockSkew)) || iat.isBefore(now.minus(allowedClockSkew))) {
            throw invalidClient("Client Attestation PoP \"iat\" is not fresh: " + iat);
        }

        if (challengeService.isPresent()) {
            Object challengeClaim = popClaims.getClaim(ClientAttestation.CHALLENGE_CLAIM_NAME);
            String challenge = challengeClaim instanceof String s ? s : null;
            if (challenge == null || challenge.isBlank() || !challengeService.get().tryConsume(challenge)) {
                throw new AttestationChallengeRequiredException(challengeService.get().issue(),
                        "Client Attestation PoP is missing a valid, unconsumed \"challenge\" claim");
            }
        }

        String jti = popClaims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw invalidClient("Client Attestation PoP is missing required \"jti\" claim");
        }
        if (!popReplayStore.recordUse(jti, now, now.plus(allowedClockSkew.multipliedBy(2)))) {
            throw invalidClient("Client Attestation PoP \"jti\" has already been used");
        }

        return clientId;
    }

    private static SignedJWT parse(String jwt, String label) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, label + " is not a well-formed JWT", e);
        }
    }

    private static void requireType(SignedJWT jwt, String expectedTyp, String label) {
        if (jwt.getHeader().getType() == null || !expectedTyp.equals(jwt.getHeader().getType().getType())) {
            throw invalidClient(label + " \"typ\" header must be \"" + expectedTyp + "\"");
        }
    }

    private static void verifySignature(SignedJWT jwt, ECKey key, String label) {
        try {
            if (!jwt.verify(new ECDSAVerifier(key.toPublicJWK()))) {
                throw invalidClient(label + " signature verification failed");
            }
        } catch (JOSEException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, label + " signature verification failed", e);
        }
    }

    private static JWTClaimsSet claims(SignedJWT jwt, String label) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, label + " claims could not be parsed", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static ECKey readConfirmationKey(JWTClaimsSet claims) {
        Object cnf = claims.getClaim("cnf");
        if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map<?, ?> jwkMap)) {
            throw invalidClient("Client Attestation is missing required \"cnf.jwk\" claim");
        }
        try {
            JWK jwk = JWK.parse((Map<String, Object>) jwkMap);
            if (!(jwk instanceof ECKey ecKey)) {
                throw invalidClient("Client Attestation \"cnf.jwk\" must be an EC key");
            }
            return ecKey;
        } catch (ParseException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, "Client Attestation \"cnf.jwk\" could not be parsed", e);
        }
    }

    private static Oid4vciException invalidClient(String message) {
        return new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, message);
    }
}
