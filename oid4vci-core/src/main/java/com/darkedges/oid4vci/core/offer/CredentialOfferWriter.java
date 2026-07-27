package com.darkedges.oid4vci.core.offer;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link CredentialOffer} back to its JSON representation, the inverse of
 * {@link CredentialOfferReader}. */
public final class CredentialOfferWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    private static final String PRE_AUTHORIZED_CODE_GRANT_URN = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    private static final String AUTHORIZATION_CODE_GRANT_URN = "authorization_code";

    private CredentialOfferWriter() {}

    public static ObjectNode write(CredentialOffer offer) {
        ObjectNode root = NODES.objectNode();
        root.put("credential_issuer", offer.credentialIssuer().toString());
        ArrayNode ids = root.putArray("credential_configuration_ids");
        offer.credentialConfigurationIds().forEach(ids::add);
        offer.grants().ifPresent(grants -> root.set("grants", writeGrants(grants)));
        return root;
    }

    private static ObjectNode writeGrants(Grants grants) {
        ObjectNode node = NODES.objectNode();
        grants.authorizationCode().ifPresent(g -> node.set(AUTHORIZATION_CODE_GRANT_URN, writeAuthorizationCodeGrant(g)));
        grants.preAuthorizedCode().ifPresent(g -> node.set(PRE_AUTHORIZED_CODE_GRANT_URN, writePreAuthorizedCodeGrant(g)));
        return node;
    }

    private static ObjectNode writeAuthorizationCodeGrant(AuthorizationCodeGrant grant) {
        ObjectNode node = NODES.objectNode();
        grant.issuerState().ifPresent(v -> node.put("issuer_state", v));
        grant.authorizationServer().ifPresent(v -> node.put("authorization_server", v.toString()));
        return node;
    }

    private static ObjectNode writePreAuthorizedCodeGrant(PreAuthorizedCodeGrant grant) {
        ObjectNode node = NODES.objectNode();
        node.put("pre-authorized_code", grant.preAuthorizedCode());
        grant.txCode().ifPresent(txCode -> node.set("tx_code", writeTxCode(txCode)));
        grant.authorizationServer().ifPresent(v -> node.put("authorization_server", v.toString()));
        return node;
    }

    private static ObjectNode writeTxCode(TxCode txCode) {
        ObjectNode node = NODES.objectNode();
        txCode.inputMode().ifPresent(v -> node.put("input_mode", v.value()));
        txCode.length().ifPresent(v -> node.put("length", v));
        txCode.description().ifPresent(v -> node.put("description", v));
        return node;
    }
}
