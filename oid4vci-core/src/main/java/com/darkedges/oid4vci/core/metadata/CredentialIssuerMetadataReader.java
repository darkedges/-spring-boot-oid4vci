package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Parses a {@link CredentialIssuerMetadata} from its JSON representation. */
public final class CredentialIssuerMetadataReader {

    private CredentialIssuerMetadataReader() {}

    public static CredentialIssuerMetadata read(JsonNode root) {
        URI credentialIssuer = URI.create(root.required("credential_issuer").asText());
        URI credentialEndpoint = URI.create(root.required("credential_endpoint").asText());
        Optional<URI> nonceEndpoint = readOptionalUri(root, "nonce_endpoint");
        Optional<URI> deferredCredentialEndpoint = readOptionalUri(root, "deferred_credential_endpoint");

        List<URI> authorizationServers = new ArrayList<>();
        if (root.hasNonNull("authorization_servers")) {
            root.get("authorization_servers").forEach(n -> authorizationServers.add(URI.create(n.asText())));
        }

        return new CredentialIssuerMetadata(
                credentialIssuer, credentialEndpoint, nonceEndpoint, deferredCredentialEndpoint,
                authorizationServers, readConfigurationsSupported(root), readBatchCredentialIssuance(root));
    }

    private static Optional<BatchCredentialIssuance> readBatchCredentialIssuance(JsonNode root) {
        return root.hasNonNull("batch_credential_issuance")
                ? Optional.of(new BatchCredentialIssuance(root.get("batch_credential_issuance").required("batch_size").asInt()))
                : Optional.empty();
    }

    /** Just the {@code credential_configurations_supported} map — for building a
     * {@link CredentialIssuerMetadataTemplate}, which has no URI fields of its own to parse. */
    public static Map<String, CredentialConfiguration> readConfigurationsSupported(JsonNode root) {
        Map<String, CredentialConfiguration> configurations = new LinkedHashMap<>();
        root.required("credential_configurations_supported").fields().forEachRemaining(
                entry -> configurations.put(entry.getKey(), readConfiguration(entry.getValue())));
        return configurations;
    }

    private static CredentialConfiguration readConfiguration(JsonNode node) {
        CredentialFormat format = CredentialFormat.fromIdentifier(node.required("format").asText());
        List<ClaimDescription> claims = readClaims(node);
        Map<ProofType, ProofTypeSupported> proofTypes = readProofTypes(node);
        List<String> signingAlgs = readStringArray(node.path("credential_signing_alg_values_supported"));
        List<String> bindingMethods = readStringArray(node.path("cryptographic_binding_methods_supported"));
        Optional<String> scope = node.hasNonNull("scope") ? Optional.of(node.get("scope").asText()) : Optional.empty();

        return switch (format) {
            case DC_SD_JWT -> new SdJwtVcCredentialConfiguration(
                    node.required("vct").asText(), claims, proofTypes, signingAlgs, bindingMethods, scope);
            case MSO_MDOC -> new MsoMdocCredentialConfiguration(
                    node.required("doctype").asText(), claims, proofTypes, signingAlgs, bindingMethods, scope);
            case JWT_VC_JSON, LDP_VC -> throw new IllegalArgumentException(
                    "credential_configurations_supported format not yet supported by this model: " + format);
        };
    }

    /** Checks the format-specific top-level {@code claims} first (only {@code dc+sd-jwt} has one, per
     * OID4VCI 1.0 Final Appendix B.2), then falls back to the generic {@code credential_metadata.claims}
     * every other format uses (Appendix B.1) — see {@link CredentialIssuerMetadataWriter}'s Javadoc for
     * why the two locations exist. */
    private static List<ClaimDescription> readClaims(JsonNode configNode) {
        JsonNode claimsNode = configNode.hasNonNull("claims") ? configNode.get("claims") : null;
        if (claimsNode == null && configNode.hasNonNull("credential_metadata")) {
            JsonNode credentialMetadata = configNode.get("credential_metadata");
            claimsNode = credentialMetadata.hasNonNull("claims") ? credentialMetadata.get("claims") : null;
        }

        List<ClaimDescription> claims = new ArrayList<>();
        if (claimsNode != null) {
            for (JsonNode claimNode : claimsNode) {
                ClaimsPathPointer path = ClaimsPathPointer.parse(claimNode.required("path"));
                Optional<Boolean> mandatory = claimNode.hasNonNull("mandatory")
                        ? Optional.of(claimNode.get("mandatory").asBoolean())
                        : Optional.empty();
                claims.add(new ClaimDescription(path, mandatory));
            }
        }
        return claims;
    }

    private static Map<ProofType, ProofTypeSupported> readProofTypes(JsonNode configNode) {
        Map<ProofType, ProofTypeSupported> proofTypes = new HashMap<>();
        if (configNode.hasNonNull("proof_types_supported")) {
            configNode.get("proof_types_supported").fields().forEachRemaining(entry -> proofTypes.put(
                    ProofType.fromValue(entry.getKey()),
                    new ProofTypeSupported(readStringArray(entry.getValue().path("proof_signing_alg_values_supported")))));
        }
        return proofTypes;
    }

    private static Optional<URI> readOptionalUri(JsonNode root, String field) {
        return root.hasNonNull(field) ? Optional.of(URI.create(root.get(field).asText())) : Optional.empty();
    }

    private static List<String> readStringArray(JsonNode arrayNode) {
        List<String> values = new ArrayList<>();
        if (arrayNode != null && arrayNode.isArray()) {
            arrayNode.forEach(n -> values.add(n.asText()));
        }
        return values;
    }
}
