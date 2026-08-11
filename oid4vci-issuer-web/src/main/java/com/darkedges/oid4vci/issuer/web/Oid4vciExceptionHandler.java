package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.error.AttestationChallengeRequiredException;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.issuer.NonceService;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps {@link Oid4vciException} to the OAuth2-shaped {@code {"error": "..."}} JSON body OID4VCI's Token
 * and Credential Endpoints use, with the HTTP status RFC 6749/OID4VCI expects per error code.
 *
 * <p>For {@code invalid_proof}/{@code invalid_nonce} (Section 8.3.1), also embeds a fresh {@code c_nonce}
 * in the error body: the spec allows this so the Wallet can immediately retry the Credential Request
 * with a corrected proof, without a separate round trip to the Nonce Endpoint first.
 *
 * <p>{@link AttestationChallengeRequiredException} (a distinct {@code use_attestation_challenge} case —
 * draft-ietf-oauth-attestation-based-client-auth Section 6.3) gets its own, more specific handler method:
 * Spring MVC dispatches to it in preference to the general one below, since it carries a fresh Challenge
 * that must go out via the {@code OAuth-Client-Attestation-Challenge} response header, not the body.
 *
 * <p>Returns a pre-serialized {@code String} — see {@link IssuerMetadataController}'s Javadoc for why.
 */
@RestControllerAdvice
public class Oid4vciExceptionHandler {

    private final NonceService nonceService;

    public Oid4vciExceptionHandler(NonceService nonceService) {
        this.nonceService = nonceService;
    }

    @ExceptionHandler(AttestationChallengeRequiredException.class)
    public ResponseEntity<String> handle(AttestationChallengeRequiredException e) {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("error", e.errorCode().value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .header(ClientAttestation.CHALLENGE_HEADER_NAME, e.challenge())
                .body(body.toString());
    }

    @ExceptionHandler(Oid4vciException.class)
    public ResponseEntity<String> handle(Oid4vciException e) {
        HttpStatus status = e.errorCode() == Oid4vciErrorCode.INVALID_TOKEN || e.errorCode() == Oid4vciErrorCode.INVALID_CLIENT
                ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST;
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("error", e.errorCode().value());
        if (e.errorCode() == Oid4vciErrorCode.INVALID_PROOF || e.errorCode() == Oid4vciErrorCode.INVALID_NONCE) {
            body.put("c_nonce", nonceService.issue());
        }
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body.toString());
    }
}
