package com.darkedges.oid4vci.core.metadata;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Collection;

/** Serializes an {@link AuthorizationServerMetadata} to its JSON representation (RFC 8414). */
public final class AuthorizationServerMetadataWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private AuthorizationServerMetadataWriter() {}

    public static ObjectNode write(AuthorizationServerMetadata metadata) {
        ObjectNode root = NODES.objectNode();
        root.put("issuer", metadata.issuer().toString());
        root.put("token_endpoint", metadata.tokenEndpoint().toString());
        root.put("jwks_uri", metadata.jwksUri().toString());
        metadata.authorizationEndpoint().ifPresent(uri -> root.put("authorization_endpoint", uri.toString()));
        metadata.pushedAuthorizationRequestEndpoint()
                .ifPresent(uri -> root.put("pushed_authorization_request_endpoint", uri.toString()));
        putStringArray(root, "grant_types_supported", metadata.grantTypesSupported());
        if (!metadata.responseTypesSupported().isEmpty()) {
            putStringArray(root, "response_types_supported", metadata.responseTypesSupported());
        }
        if (!metadata.codeChallengeMethodsSupported().isEmpty()) {
            putStringArray(root, "code_challenge_methods_supported", metadata.codeChallengeMethodsSupported());
        }
        putStringArray(root, "token_endpoint_auth_methods_supported", metadata.tokenEndpointAuthMethodsSupported());
        putStringArray(root, "dpop_signing_alg_values_supported", metadata.dpopSigningAlgValuesSupported());
        putStringArray(root, "authorization_details_types_supported", metadata.authorizationDetailsTypesSupported());
        // Genuinely conditional, unlike the arrays above (always non-empty in practice): omit entirely
        // rather than emit an empty array when attest_jwt_client_auth isn't supported.
        if (!metadata.clientAttestationSigningAlgValuesSupported().isEmpty()) {
            putStringArray(root, "client_attestation_signing_alg_values_supported",
                    metadata.clientAttestationSigningAlgValuesSupported());
        }
        if (!metadata.clientAttestationPopSigningAlgValuesSupported().isEmpty()) {
            putStringArray(root, "client_attestation_pop_signing_alg_values_supported",
                    metadata.clientAttestationPopSigningAlgValuesSupported());
        }
        metadata.challengeEndpoint().ifPresent(uri -> root.put("challenge_endpoint", uri.toString()));
        return root;
    }

    private static void putStringArray(ObjectNode root, String field, Collection<String> values) {
        ArrayNode array = root.putArray(field);
        values.forEach(array::add);
    }
}
