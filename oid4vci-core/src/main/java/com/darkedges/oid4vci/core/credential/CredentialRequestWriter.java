package com.darkedges.oid4vci.core.credential;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link CredentialRequest} back to its JSON representation, the inverse of
 * {@link CredentialRequestReader}. */
public final class CredentialRequestWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private CredentialRequestWriter() {}

    public static ObjectNode write(CredentialRequest request) {
        ObjectNode root = NODES.objectNode();
        request.credentialConfigurationId().ifPresent(v -> root.put("credential_configuration_id", v));
        request.credentialIdentifier().ifPresent(v -> root.put("credential_identifier", v));
        request.proofs().ifPresent(proofs -> root.set("proofs", writeProofs(proofs)));
        return root;
    }

    private static ObjectNode writeProofs(Proofs proofs) {
        ObjectNode node = NODES.objectNode();
        proofs.jwt().ifPresent(jwts -> {
            ArrayNode array = node.putArray("jwt");
            jwts.forEach(array::add);
        });
        return node;
    }
}
