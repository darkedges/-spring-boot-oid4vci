package com.darkedges.oid4vci.core.metadata;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * The host-independent shape of an {@link AuthorizationServerMetadata} document — everything except the
 * base URL itself. See {@link CredentialIssuerMetadataTemplate}'s Javadoc for why this issuer has no
 * single fixed base URL baked into its own config.
 */
public record AuthorizationServerMetadataTemplate(
        String tokenEndpointPath,
        String jwksUriPath,
        Optional<String> authorizationEndpointPath,
        Optional<String> pushedAuthorizationRequestEndpointPath,
        List<String> grantTypesSupported,
        List<String> responseTypesSupported,
        List<String> codeChallengeMethodsSupported,
        List<String> tokenEndpointAuthMethodsSupported,
        List<String> dpopSigningAlgValuesSupported,
        List<String> authorizationDetailsTypesSupported,
        List<String> clientAttestationSigningAlgValuesSupported,
        List<String> clientAttestationPopSigningAlgValuesSupported,
        Optional<String> challengeEndpointPath) {

    public AuthorizationServerMetadataTemplate {
        if (tokenEndpointPath == null || tokenEndpointPath.isBlank()) {
            throw new IllegalArgumentException("tokenEndpointPath is required");
        }
        if (jwksUriPath == null || jwksUriPath.isBlank()) {
            throw new IllegalArgumentException("jwksUriPath is required");
        }
        authorizationEndpointPath = authorizationEndpointPath == null ? Optional.empty() : authorizationEndpointPath;
        pushedAuthorizationRequestEndpointPath = pushedAuthorizationRequestEndpointPath == null
                ? Optional.empty() : pushedAuthorizationRequestEndpointPath;
        grantTypesSupported = grantTypesSupported == null ? List.of() : List.copyOf(grantTypesSupported);
        responseTypesSupported = responseTypesSupported == null ? List.of() : List.copyOf(responseTypesSupported);
        codeChallengeMethodsSupported = codeChallengeMethodsSupported == null
                ? List.of() : List.copyOf(codeChallengeMethodsSupported);
        tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported == null
                ? List.of() : List.copyOf(tokenEndpointAuthMethodsSupported);
        dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported == null
                ? List.of() : List.copyOf(dpopSigningAlgValuesSupported);
        authorizationDetailsTypesSupported = authorizationDetailsTypesSupported == null
                ? List.of() : List.copyOf(authorizationDetailsTypesSupported);
        clientAttestationSigningAlgValuesSupported = clientAttestationSigningAlgValuesSupported == null
                ? List.of() : List.copyOf(clientAttestationSigningAlgValuesSupported);
        clientAttestationPopSigningAlgValuesSupported = clientAttestationPopSigningAlgValuesSupported == null
                ? List.of() : List.copyOf(clientAttestationPopSigningAlgValuesSupported);
        challengeEndpointPath = challengeEndpointPath == null ? Optional.empty() : challengeEndpointPath;
    }

    /** Builds the full metadata document as it should be advertised to a client that reached this issuer
     * at {@code baseUrl} (no trailing slash, e.g. {@code https://issuer.zkp.au}). */
    public AuthorizationServerMetadata resolve(String baseUrl) {
        return new AuthorizationServerMetadata(
                URI.create(baseUrl),
                URI.create(baseUrl + tokenEndpointPath),
                URI.create(baseUrl + jwksUriPath),
                authorizationEndpointPath.map(path -> URI.create(baseUrl + path)),
                pushedAuthorizationRequestEndpointPath.map(path -> URI.create(baseUrl + path)),
                grantTypesSupported, responseTypesSupported, codeChallengeMethodsSupported,
                tokenEndpointAuthMethodsSupported, dpopSigningAlgValuesSupported,
                authorizationDetailsTypesSupported, clientAttestationSigningAlgValuesSupported,
                clientAttestationPopSigningAlgValuesSupported,
                challengeEndpointPath.map(path -> URI.create(baseUrl + path)));
    }
}
