package com.darkedges.oid4vci.core.token;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** A Token Endpoint {@code grant_type} value (OID4VCI 1.0, Section 6). Only
 * {@link #PRE_AUTHORIZED_CODE} is driven by any v1 code path; {@link #AUTHORIZATION_CODE} is modeled so
 * a Credential Offer/Token Request referencing it still parses. */
public enum GrantType {
    PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
    AUTHORIZATION_CODE("authorization_code");

    private final String value;

    GrantType(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static GrantType fromValue(String value) {
        for (GrantType type : values()) {
            if (type.value.equals(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown grant_type: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
