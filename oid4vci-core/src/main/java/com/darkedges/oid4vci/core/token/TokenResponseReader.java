package com.darkedges.oid4vci.core.token;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Parses a {@link TokenResponse} from its JSON representation. */
public final class TokenResponseReader {

    private TokenResponseReader() {}

    public static TokenResponse read(JsonNode root) {
        String accessToken = root.required("access_token").asText();
        String tokenType = root.required("token_type").asText();
        Optional<Long> expiresIn = root.hasNonNull("expires_in")
                ? Optional.of(root.get("expires_in").asLong())
                : Optional.empty();

        Optional<List<AuthorizationDetail>> authorizationDetails = Optional.empty();
        if (root.hasNonNull("authorization_details")) {
            List<AuthorizationDetail> list = new ArrayList<>();
            for (JsonNode node : root.get("authorization_details")) {
                list.add(readAuthorizationDetail(node));
            }
            authorizationDetails = Optional.of(list);
        }

        return new TokenResponse(accessToken, tokenType, expiresIn, authorizationDetails);
    }

    private static AuthorizationDetail readAuthorizationDetail(JsonNode node) {
        String type = node.required("type").asText();
        if (!AuthorizationDetail.TYPE.equals(type)) {
            throw new IllegalArgumentException("authorization_details[].type must be \"" + AuthorizationDetail.TYPE + "\", was: " + type);
        }
        String configurationId = node.required("credential_configuration_id").asText();
        Optional<List<String>> identifiers = Optional.empty();
        if (node.hasNonNull("credential_identifiers")) {
            List<String> list = new ArrayList<>();
            node.get("credential_identifiers").forEach(n -> list.add(n.asText()));
            identifiers = Optional.of(list);
        }
        return new AuthorizationDetail(configurationId, identifiers);
    }
}
