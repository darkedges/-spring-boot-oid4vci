package com.darkedges.oid4vci.core.offer;

import java.util.Optional;

/**
 * {@code tx_code} (OID4VCI 1.0, Section 4.1.1) — describes (but does not carry) a transaction code the
 * End-User must additionally enter, e.g. one delivered out-of-band via e-mail/SMS.
 *
 * @param inputMode   OPTIONAL, defaults to {@link TxCodeInputMode#NUMERIC} at the point of use if absent.
 * @param length      OPTIONAL expected code length, for UI purposes only — not enforced by this model.
 * @param description OPTIONAL guidance text for the End-User.
 */
public record TxCode(Optional<TxCodeInputMode> inputMode, Optional<Integer> length, Optional<String> description) {

    public TxCode {
        inputMode = inputMode == null ? Optional.empty() : inputMode;
        length = length == null ? Optional.empty() : length;
        description = description == null ? Optional.empty() : description;
    }
}
