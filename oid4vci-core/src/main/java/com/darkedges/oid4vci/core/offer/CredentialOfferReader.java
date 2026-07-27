package com.darkedges.oid4vci.core.offer;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Parses a {@link CredentialOffer} from its JSON representation. */
public final class CredentialOfferReader {

    private static final String PRE_AUTHORIZED_CODE_GRANT_URN = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    private static final String AUTHORIZATION_CODE_GRANT_URN = "authorization_code";

    private CredentialOfferReader() {}

    public static CredentialOffer read(JsonNode root) {
        URI credentialIssuer = URI.create(root.required("credential_issuer").asText());

        List<String> configurationIds = new ArrayList<>();
        for (JsonNode node : root.required("credential_configuration_ids")) {
            configurationIds.add(node.asText());
        }

        Optional<Grants> grants = root.hasNonNull("grants")
                ? Optional.of(readGrants(root.get("grants")))
                : Optional.empty();

        return new CredentialOffer(credentialIssuer, configurationIds, grants);
    }

    private static Grants readGrants(JsonNode node) {
        Optional<AuthorizationCodeGrant> authorizationCode = node.hasNonNull(AUTHORIZATION_CODE_GRANT_URN)
                ? Optional.of(readAuthorizationCodeGrant(node.get(AUTHORIZATION_CODE_GRANT_URN)))
                : Optional.empty();
        Optional<PreAuthorizedCodeGrant> preAuthorizedCode = node.hasNonNull(PRE_AUTHORIZED_CODE_GRANT_URN)
                ? Optional.of(readPreAuthorizedCodeGrant(node.get(PRE_AUTHORIZED_CODE_GRANT_URN)))
                : Optional.empty();
        return new Grants(authorizationCode, preAuthorizedCode);
    }

    private static AuthorizationCodeGrant readAuthorizationCodeGrant(JsonNode node) {
        Optional<String> issuerState = node.hasNonNull("issuer_state")
                ? Optional.of(node.get("issuer_state").asText())
                : Optional.empty();
        return new AuthorizationCodeGrant(issuerState, readAuthorizationServer(node));
    }

    private static PreAuthorizedCodeGrant readPreAuthorizedCodeGrant(JsonNode node) {
        String preAuthorizedCode = node.required("pre-authorized_code").asText();
        Optional<TxCode> txCode = node.hasNonNull("tx_code")
                ? Optional.of(readTxCode(node.get("tx_code")))
                : Optional.empty();
        return new PreAuthorizedCodeGrant(preAuthorizedCode, txCode, readAuthorizationServer(node));
    }

    private static TxCode readTxCode(JsonNode node) {
        Optional<TxCodeInputMode> inputMode = node.hasNonNull("input_mode")
                ? Optional.of(TxCodeInputMode.fromValue(node.get("input_mode").asText()))
                : Optional.empty();
        Optional<Integer> length = node.hasNonNull("length")
                ? Optional.of(node.get("length").asInt())
                : Optional.empty();
        Optional<String> description = node.hasNonNull("description")
                ? Optional.of(node.get("description").asText())
                : Optional.empty();
        return new TxCode(inputMode, length, description);
    }

    private static Optional<URI> readAuthorizationServer(JsonNode node) {
        return node.hasNonNull("authorization_server")
                ? Optional.of(URI.create(node.get("authorization_server").asText()))
                : Optional.empty();
    }
}
