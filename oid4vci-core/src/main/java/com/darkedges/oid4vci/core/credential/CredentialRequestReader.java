package com.darkedges.oid4vci.core.credential;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Parses a {@link CredentialRequest} from its JSON representation. */
public final class CredentialRequestReader {

    private CredentialRequestReader() {}

    public static CredentialRequest read(JsonNode root) {
        Optional<String> configurationId = root.hasNonNull("credential_configuration_id")
                ? Optional.of(root.get("credential_configuration_id").asText())
                : Optional.empty();
        Optional<String> identifier = root.hasNonNull("credential_identifier")
                ? Optional.of(root.get("credential_identifier").asText())
                : Optional.empty();
        Optional<Proofs> proofs = root.hasNonNull("proofs")
                ? Optional.of(readProofs(root.get("proofs")))
                : Optional.empty();
        return new CredentialRequest(configurationId, identifier, proofs);
    }

    private static Proofs readProofs(JsonNode node) {
        Optional<List<String>> jwt = Optional.empty();
        if (node.hasNonNull("jwt")) {
            List<String> list = new ArrayList<>();
            node.get("jwt").forEach(n -> list.add(n.asText()));
            jwt = Optional.of(list);
        }
        return new Proofs(jwt);
    }
}
