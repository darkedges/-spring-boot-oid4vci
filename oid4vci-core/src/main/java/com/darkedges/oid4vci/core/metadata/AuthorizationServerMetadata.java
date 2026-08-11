package com.darkedges.oid4vci.core.metadata;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * The Authorization Server Metadata document (RFC 8414) served at
 * {@code /.well-known/oauth-authorization-server} — needed because {@link CredentialIssuerMetadata}
 * having no {@code authorization_servers} entry means the Credential Issuer is its own Authorization
 * Server (OID4VCI 1.0, Section 12), and a Wallet (or the OpenID Conformance Suite) then discovers the
 * Token Endpoint by fetching this document at the Credential Issuer's own identifier, per RFC 8414's
 * well-known URI construction.
 *
 * <p>{@code authorizationEndpoint}/{@code responseTypesSupported}/{@code codeChallengeMethodsSupported}
 * are only present when this issuer has an {@code AuthorizationClaimsResolver} bean wired up (see
 * {@code Oid4vciIssuerAutoConfiguration}) — without one there's no way to decide what claim values an
 * {@code authorization_code} grant's credential should carry (no login exists in this project at all;
 * see {@code AuthorizationEndpointController}'s Javadoc), so the grant, and everything that advertises
 * it, stays unwired rather than existing half-broken.
 *
 * @param issuer                             REQUIRED — identical to {@link CredentialIssuerMetadata#credentialIssuer()}.
 * @param tokenEndpoint                      REQUIRED.
 * @param jwksUri                            RECOMMENDED.
 * @param authorizationEndpoint              RFC 8414 — required when {@code authorization_code} is in
 *                                           {@code grantTypesSupported}; absent (and omitted from the
 *                                           JSON) otherwise, since this issuer then has no front-channel
 *                                           endpoint to advertise at all.
 * @param pushedAuthorizationRequestEndpoint RFC 9126 — present alongside {@code authorizationEndpoint}.
 *                                           Not mandatory to use (this issuer's Authorization Endpoint
 *                                           still accepts a request inline too), but every {@code vci10issuer}
 *                                           conformance test module always pushes first regardless of
 *                                           variant (confirmed against the suite's own
 *                                           {@code VCIProfileBehavior#initializeVariants}, which sets
 *                                           {@code isPar = true} unconditionally) — omitting this made
 *                                           every one of them fail at {@code CallPAREndpoint} before ever
 *                                           reaching the Authorization Endpoint.
 * @param grantTypesSupported                e.g. {@code urn:ietf:params:oauth:grant-type:pre-authorized_code}.
 * @param responseTypesSupported             RFC 8414 — {@code ["code"]} when {@code authorizationEndpoint}
 *                                           is present, empty otherwise.
 * @param codeChallengeMethodsSupported      RFC 7636 — {@code ["S256"]} when {@code authorizationEndpoint}
 *                                           is present (PKCE is mandatory on this issuer's Authorization
 *                                           Endpoint, not merely advertised as optional), empty otherwise.
 * @param tokenEndpointAuthMethodsSupported  {@code none} — the Token Endpoint authenticates the
 *                                           pre-authorized code itself, not a client credential.
 * @param dpopSigningAlgValuesSupported      RFC 9449 Section 5.1 — advertises DPoP support.
 * @param authorizationDetailsTypesSupported RFC 9396 Rich Authorization Requests metadata; OID4VCI 1.0
 *                                           Section 8.3.4 requires the AS to list {@code openid_credential}
 *                                           here so a client that never sends an OAuth {@code scope} still
 *                                           has a defined way to request credential issuance.
 * @param clientAttestationSigningAlgValuesSupported JWS {@code alg} values accepted for the Client
 *                                           Attestation JWT (see {@code ClientAttestationValidator}).
 *                                           draft-ietf-oauth-attestation-based-client-auth Section 7.1
 *                                           requires this (and the PoP equivalent below) whenever
 *                                           {@code attest_jwt_client_auth} is advertised; empty (and
 *                                           omitted from the JSON) when it isn't — note this is a
 *                                           dedicated field, not the generic RFC 8414
 *                                           {@code token_endpoint_auth_signing_alg_values_supported}
 *                                           (confirmed against the OpenID Conformance Suite's own
 *                                           {@code CheckDiscEndpointClientAttestationSigningAlgValuesSupported}).
 * @param clientAttestationPopSigningAlgValuesSupported As above, for the Client Attestation PoP JWT.
 * @param challengeEndpoint                  draft-ietf-oauth-attestation-based-client-auth Section 6.1 —
 *                                           OPTIONAL. Present only when this Authorization Server offers
 *                                           a Challenge Endpoint (see {@code ChallengeController}) for
 *                                           the Wallet to fetch a fresh, single-use Challenge to embed in
 *                                           its Client Attestation PoP JWT.
 */
public record AuthorizationServerMetadata(
        URI issuer,
        URI tokenEndpoint,
        URI jwksUri,
        Optional<URI> authorizationEndpoint,
        Optional<URI> pushedAuthorizationRequestEndpoint,
        List<String> grantTypesSupported,
        List<String> responseTypesSupported,
        List<String> codeChallengeMethodsSupported,
        List<String> tokenEndpointAuthMethodsSupported,
        List<String> dpopSigningAlgValuesSupported,
        List<String> authorizationDetailsTypesSupported,
        List<String> clientAttestationSigningAlgValuesSupported,
        List<String> clientAttestationPopSigningAlgValuesSupported,
        Optional<URI> challengeEndpoint) {

    public AuthorizationServerMetadata {
        if (issuer == null) {
            throw new IllegalArgumentException("issuer is required");
        }
        if (tokenEndpoint == null) {
            throw new IllegalArgumentException("token_endpoint is required");
        }
        authorizationEndpoint = authorizationEndpoint == null ? Optional.empty() : authorizationEndpoint;
        pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint == null
                ? Optional.empty() : pushedAuthorizationRequestEndpoint;
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
        challengeEndpoint = challengeEndpoint == null ? Optional.empty() : challengeEndpoint;
    }
}
