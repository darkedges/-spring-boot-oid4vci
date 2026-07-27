package com.darkedges.oid4vci.core.credential;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Parses a {@link CredentialResponse} from its JSON representation. */
public final class CredentialResponseReader {

    private CredentialResponseReader() {}

    public static CredentialResponse read(JsonNode root) {
        Optional<List<IssuedCredential>> credentials = Optional.empty();
        if (root.hasNonNull("credentials")) {
            List<IssuedCredential> list = new ArrayList<>();
            root.get("credentials").forEach(n -> list.add(new IssuedCredential(n.required("credential").asText())));
            credentials = Optional.of(list);
        }
        Optional<String> transactionId = root.hasNonNull("transaction_id")
                ? Optional.of(root.get("transaction_id").asText())
                : Optional.empty();
        return new CredentialResponse(credentials, transactionId);
    }
}
