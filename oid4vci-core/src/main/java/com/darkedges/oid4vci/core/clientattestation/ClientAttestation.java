package com.darkedges.oid4vci.core.clientattestation;

/**
 * Wire constants for OAuth 2.0 Attestation-Based Client Authentication ({@code attest_jwt_client_auth},
 * draft-ietf-oauth-attestation-based-client-auth): a Wallet authenticates to the Token Endpoint with two
 * JWTs instead of a client secret — a Client Attestation JWT (issued by a trusted Wallet Provider,
 * vouching for the Wallet instance's public key) and a Client Attestation PoP JWT (signed by that Wallet
 * instance's own key, proving possession of it for this specific request) — sent as two request headers
 * rather than bundled into a single {@code client_assertion} parameter like {@code private_key_jwt}.
 */
public final class ClientAttestation {

    public static final String ATTESTATION_HEADER_NAME = "OAuth-Client-Attestation";
    public static final String ATTESTATION_POP_HEADER_NAME = "OAuth-Client-Attestation-PoP";
    public static final String ATTESTATION_TYP = "oauth-client-attestation+jwt";
    public static final String ATTESTATION_POP_TYP = "oauth-client-attestation-pop+jwt";
    public static final String AUTH_METHOD = "attest_jwt_client_auth";

    /** draft-ietf-oauth-attestation-based-client-auth Section 6.2 — the response header an Authorization
     * Server carrying a fresh Challenge (e.g. on a {@code use_attestation_challenge} error) MUST use. */
    public static final String CHALLENGE_HEADER_NAME = "OAuth-Client-Attestation-Challenge";

    /** draft-ietf-oauth-attestation-based-client-auth Section 5.2 — the Client Attestation PoP JWT claim
     * carrying a server-provided Challenge (see {@code ChallengeController}), when the Authorization
     * Server requires one. */
    public static final String CHALLENGE_CLAIM_NAME = "challenge";

    private ClientAttestation() {}
}
