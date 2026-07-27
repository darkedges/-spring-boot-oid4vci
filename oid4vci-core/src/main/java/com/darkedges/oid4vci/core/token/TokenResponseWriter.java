package com.darkedges.oid4vci.core.token;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link TokenResponse} back to its JSON representation, the inverse of
 * {@link TokenResponseReader}. */
public final class TokenResponseWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private TokenResponseWriter() {}

    public static ObjectNode write(TokenResponse response) {
        ObjectNode root = NODES.objectNode();
        root.put("access_token", response.accessToken());
        root.put("token_type", response.tokenType());
        response.expiresIn().ifPresent(v -> root.put("expires_in", v));
        response.authorizationDetails().ifPresent(details -> {
            ArrayNode array = root.putArray("authorization_details");
            details.forEach(d -> array.add(writeAuthorizationDetail(d)));
        });
        return root;
    }

    private static ObjectNode writeAuthorizationDetail(AuthorizationDetail detail) {
        ObjectNode node = NODES.objectNode();
        node.put("type", AuthorizationDetail.TYPE);
        node.put("credential_configuration_id", detail.credentialConfigurationId());
        detail.credentialIdentifiers().ifPresent(ids -> {
            ArrayNode array = node.putArray("credential_identifiers");
            ids.forEach(array::add);
        });
        return node;
    }
}
