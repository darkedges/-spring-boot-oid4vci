package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.AttestationChallengeService;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The Challenge Endpoint (draft-ietf-oauth-attestation-based-client-auth Section 6.1): issues a fresh,
 * single-use {@code attestation_challenge} for a Wallet to embed in its next Client Attestation PoP JWT
 * (see {@code ClientAttestationValidator}) — the same reactive-nonce shape {@link NonceController}/
 * OID4VCI's {@code c_nonce} and RFC 9449's DPoP nonce already use elsewhere in this issuer. Only
 * registered when {@code oid4vci.issuer.attestation-challenge-endpoint-path} is configured (see
 * {@code Oid4vciIssuerAutoConfiguration}) — this feature is spec-optional ({@code MAY}), and enabling it
 * unconditionally would make every existing {@code attest_jwt_client_auth} Wallet integration start
 * failing with {@code use_attestation_challenge} the moment it's turned on.
 */
@RestController
public class ChallengeController {

    private final AttestationChallengeService challengeService;

    public ChallengeController(AttestationChallengeService challengeService) {
        this.challengeService = challengeService;
    }

    @PostMapping(value = "/challenge", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> challenge() {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("attestation_challenge", challengeService.issue());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body.toString());
    }
}
