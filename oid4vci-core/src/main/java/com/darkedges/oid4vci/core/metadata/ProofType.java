package com.darkedges.oid4vci.core.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * A {@code proof_types_supported} key (OID4VCI 1.0, Appendix E). Only {@link #JWT} has a build/verify
 * implementation in this phase; the other types are modeled so metadata referencing them still parses.
 */
public enum ProofType {
    JWT("jwt"),
    LDP_VP("ldp_vp"),
    ATTESTATION("attestation");

    private final String value;

    ProofType(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static ProofType fromValue(String value) {
        for (ProofType type : values()) {
            if (type.value.equals(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown proof type: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
