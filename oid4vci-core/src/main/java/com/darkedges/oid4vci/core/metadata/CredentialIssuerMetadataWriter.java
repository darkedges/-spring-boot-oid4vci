package com.darkedges.oid4vci.core.metadata;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link CredentialIssuerMetadata} back to its JSON representation, the inverse of
 * {@link CredentialIssuerMetadataReader}. */
public final class CredentialIssuerMetadataWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private CredentialIssuerMetadataWriter() {}

    public static ObjectNode write(CredentialIssuerMetadata metadata) {
        ObjectNode root = NODES.objectNode();
        root.put("credential_issuer", metadata.credentialIssuer().toString());
        root.put("credential_endpoint", metadata.credentialEndpoint().toString());
        metadata.nonceEndpoint().ifPresent(v -> root.put("nonce_endpoint", v.toString()));
        metadata.deferredCredentialEndpoint().ifPresent(v -> root.put("deferred_credential_endpoint", v.toString()));
        if (!metadata.authorizationServers().isEmpty()) {
            ArrayNode servers = root.putArray("authorization_servers");
            metadata.authorizationServers().forEach(s -> servers.add(s.toString()));
        }
        ObjectNode configurations = root.putObject("credential_configurations_supported");
        metadata.credentialConfigurationsSupported().forEach(
                (id, configuration) -> configurations.set(id, writeConfiguration(configuration)));
        return root;
    }

    private static ObjectNode writeConfiguration(CredentialConfiguration configuration) {
        ObjectNode node = NODES.objectNode();
        switch (configuration) {
            case SdJwtVcCredentialConfiguration c -> {
                node.put("format", SdJwtVcCredentialConfiguration.WIRE_FORMAT);
                node.put("vct", c.vct());
            }
            case MsoMdocCredentialConfiguration c -> {
                node.put("format", c.format().identifier());
                node.put("doctype", c.doctype());
            }
        }
        if (!configuration.claims().isEmpty()) {
            ArrayNode claims = node.putArray("claims");
            configuration.claims().forEach(c -> claims.add(writeClaimDescription(c)));
        }
        if (!configuration.proofTypesSupported().isEmpty()) {
            ObjectNode proofTypes = node.putObject("proof_types_supported");
            configuration.proofTypesSupported().forEach((type, supported) -> {
                ObjectNode typeNode = NODES.objectNode();
                ArrayNode algs = typeNode.putArray("proof_signing_alg_values_supported");
                supported.proofSigningAlgValuesSupported().forEach(algs::add);
                proofTypes.set(type.value(), typeNode);
            });
        }
        if (!configuration.credentialSigningAlgValuesSupported().isEmpty()) {
            ArrayNode algs = node.putArray("credential_signing_alg_values_supported");
            configuration.credentialSigningAlgValuesSupported().forEach(algs::add);
        }
        if (!configuration.cryptographicBindingMethodsSupported().isEmpty()) {
            ArrayNode methods = node.putArray("cryptographic_binding_methods_supported");
            configuration.cryptographicBindingMethodsSupported().forEach(methods::add);
        }
        return node;
    }

    private static ObjectNode writeClaimDescription(ClaimDescription claim) {
        ObjectNode node = NODES.objectNode();
        node.set("path", claim.path().toJson());
        claim.mandatory().ifPresent(v -> node.put("mandatory", v));
        return node;
    }
}
