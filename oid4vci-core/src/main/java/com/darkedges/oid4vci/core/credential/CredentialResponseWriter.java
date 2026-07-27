package com.darkedges.oid4vci.core.credential;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link CredentialResponse} back to its JSON representation, the inverse of
 * {@link CredentialResponseReader}. */
public final class CredentialResponseWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private CredentialResponseWriter() {}

    public static ObjectNode write(CredentialResponse response) {
        ObjectNode root = NODES.objectNode();
        response.credentials().ifPresent(credentials -> {
            ArrayNode array = root.putArray("credentials");
            credentials.forEach(c -> {
                ObjectNode node = NODES.objectNode();
                node.put("credential", c.credential());
                array.add(node);
            });
        });
        response.transactionId().ifPresent(v -> root.put("transaction_id", v));
        return root;
    }
}
