package com.darkedges.oid4vci.core.token;

import com.fasterxml.jackson.databind.JsonNode;

/** Parses a {@link NonceResponse} from its JSON representation. */
public final class NonceResponseReader {

    private NonceResponseReader() {}

    public static NonceResponse read(JsonNode root) {
        return new NonceResponse(root.required("c_nonce").asText());
    }
}
