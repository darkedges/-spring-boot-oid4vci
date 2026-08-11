package com.darkedges.oid4vci.core.error;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** OID4VCI 1.0 {@code error} codes (Token Endpoint and Credential Endpoint error responses). */
public enum Oid4vciErrorCode {
    INVALID_REQUEST("invalid_request"),
    INVALID_GRANT("invalid_grant"),
    /** RFC 6749 Section 5.2 — Token Endpoint rejection of a {@code grant_type} this issuer doesn't
     * implement at all (neither {@code pre-authorized_code} nor, when wired up, {@code authorization_code}). */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
    INVALID_TOKEN("invalid_token"),
    /** RFC 6749 Section 5.2 — Token Endpoint rejection of a failed client authentication attempt, e.g. an
     * invalid/missing OAuth 2.0 Attestation-Based Client Authentication proof (see
     * {@code ClientAttestationValidator}). */
    INVALID_CLIENT("invalid_client"),
    INVALID_PROOF("invalid_proof"),
    /** OID4VCI 1.0 Final Section 8.3.1.2 — the Credential Request's own payload is malformed, e.g. a
     * {@code proofs} array bigger than this issuer's advertised {@code batch_credential_issuance.batch_size}
     * (or, when batch issuance isn't advertised at all, more than one proof). */
    INVALID_CREDENTIAL_REQUEST("invalid_credential_request"),
    /** RFC 9449 (DPoP) Section 5.2 — Token Endpoint rejection of a malformed/invalid DPoP proof. Proof
     * failures at the Credential Endpoint instead use {@link #INVALID_TOKEN} per RFC 9449 Section 7.1. */
    INVALID_DPOP_PROOF("invalid_dpop_proof"),
    INVALID_NONCE("invalid_nonce"),
    /** draft-ietf-oauth-attestation-based-client-auth Section 6.3 — the Client Attestation PoP JWT didn't
     * carry the server-provided Challenge this Authorization Server requires (missing, invalid, expired,
     * or already-used) — see {@code AttestationChallengeRequiredException}. */
    USE_ATTESTATION_CHALLENGE("use_attestation_challenge"),
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    UNSUPPORTED_CREDENTIAL_FORMAT("unsupported_credential_format"),
    CREDENTIAL_REQUEST_DENIED("credential_request_denied");

    private final String value;

    Oid4vciErrorCode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static Oid4vciErrorCode fromValue(String value) {
        for (Oid4vciErrorCode code : values()) {
            if (code.value.equals(value)) {
                return code;
            }
        }
        throw new IllegalArgumentException("Unknown OID4VCI error code: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
