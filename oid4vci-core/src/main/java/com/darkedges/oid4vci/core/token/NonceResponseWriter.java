package com.darkedges.oid4vci.core.token;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link NonceResponse} back to its JSON representation, the inverse of
 * {@link NonceResponseReader}. */
public final class NonceResponseWriter {

    private NonceResponseWriter() {}

    public static ObjectNode write(NonceResponse response) {
        ObjectNode root = JsonNodeFactory.instance.objectNode();
        root.put("c_nonce", response.cNonce());
        return root;
    }
}
