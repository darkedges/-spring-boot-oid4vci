package com.darkedges.oid4vci.core.offer;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** {@code tx_code.input_mode} (OID4VCI 1.0, Section 4.1.1). */
public enum TxCodeInputMode {
    NUMERIC("numeric"),
    TEXT("text");

    private final String value;

    TxCodeInputMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static TxCodeInputMode fromValue(String value) {
        for (TxCodeInputMode mode : values()) {
            if (mode.value.equals(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unknown tx_code input_mode: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
