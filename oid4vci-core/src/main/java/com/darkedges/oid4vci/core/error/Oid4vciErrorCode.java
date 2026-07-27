package com.darkedges.oid4vci.core.error;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** OID4VCI 1.0 {@code error} codes (Token Endpoint and Credential Endpoint error responses). */
public enum Oid4vciErrorCode {
    INVALID_REQUEST("invalid_request"),
    INVALID_GRANT("invalid_grant"),
    INVALID_TOKEN("invalid_token"),
    INVALID_PROOF("invalid_proof"),
    INVALID_NONCE("invalid_nonce"),
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
