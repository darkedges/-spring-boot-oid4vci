package com.darkedges.oid4vci.demo.issuer;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * What the identity-proofing service reports once it has verified someone, server to server.
 *
 * <p>This arrives from the proofing backend, never from the Wallet. OID4VCI's pre-authorized code
 * grant gives a Wallet no channel to supply evidence, and inventing one would be worse than the gap:
 * a Credential Request carrying its own claims is claim injection with extra steps, and a modified
 * Wallet would mint whatever identity it liked. The same reasoning that moved DG2 decoding onto the
 * proofing server applies here.
 *
 * <p>The boolean findings are {@link Boolean} rather than {@code boolean} on purpose. The proofing
 * service reports {@code null} for a check it never reached — an absent CRL, a passport with no
 * Active Authentication — and that is a different fact from a check that ran and failed. Primitives
 * would silently render both as {@code false} and the issued credential would claim a document had
 * failed verification when nothing of the sort had happened.
 */
public record ProofingResultRequest(
        @JsonProperty("session_id") String sessionId,
        @JsonProperty("given_names") String givenNames,
        @JsonProperty("surname") String surname,
        @JsonProperty("date_of_birth") String dateOfBirth,
        @JsonProperty("document_number") String documentNumber,
        @JsonProperty("nationality") String nationality,
        @JsonProperty("issuing_state") String issuingState,
        @JsonProperty("date_of_expiry") String dateOfExpiry,
        @JsonProperty("liveness_passed") boolean livenessPassed,
        @JsonProperty("face_matched") boolean faceMatched,
        @JsonProperty("sod_signature_valid") Boolean sodSignatureValid,
        @JsonProperty("data_group_hashes_valid") Boolean dataGroupHashesValid,
        @JsonProperty("csca_validated") Boolean cscaValidated,
        @JsonProperty("revocation_checked") Boolean revocationChecked,
        @JsonProperty("portrait_from_chip") Boolean portraitFromChip,
        @JsonProperty("active_authentication_valid") Boolean activeAuthenticationValid,
        /**
         * The passport portrait as a comparable face template, or null.
         *
         * A 512-dimensional ArcFace embedding, base64. Not a photograph and not renderable as one,
         * which is why a credential can carry it: a wallet compares a live selfie against it on the
         * device, without the holder's picture travelling to every verifier that asks.
         *
         * <p>Still biometric data about a specific person, and issued into a selectively-disclosable
         * claim for that reason — a verifier that does not need to match never receives it. It is
         * closer to a fingerprint than a password: template-inversion research reconstructs a face
         * a matcher accepts from an embedding alone, and re-issuing does not undo a disclosure.
         *
         * <p>Null whenever the proofing service produced none — no model loaded, or a portrait that
         * came from the device rather than the chip. Absent rather than invented, because a template
         * derived from a device-supplied picture would put a stranger's face into a credential
         * asserting this identity.
         */
        @JsonProperty("face_template") String faceTemplate) {

    /**
     * Whether this result is good enough to mint a credential from.
     *
     * <p>Checked at the issuer even though the proofing service is only supposed to call on success.
     * An issuer that trusts a caller to have already decided is an issuer whose policy lives in
     * somebody else's codebase — and the shared secret authenticates the caller, not the reasoning
     * behind an individual result.
     *
     * <p>{@code portraitFromChip} is required, not merely reported. Without it the score describes a
     * face the device supplied rather than one decoded from the chip, so a genuine passport could be
     * paired with somebody else's selfie and the match would mean nothing.
     */
    public boolean isAcceptable() {
        return livenessPassed
                && faceMatched
                && Boolean.TRUE.equals(sodSignatureValid)
                && Boolean.TRUE.equals(dataGroupHashesValid)
                && Boolean.TRUE.equals(cscaValidated)
                && Boolean.TRUE.equals(portraitFromChip);
    }

    /**
     * Everything a credential would assert must actually be present; an empty claim is not a claim.
     *
     * <p>{@code givenNames} is absent from this list on purpose. ICAO 9303 permits a document with a
     * primary identifier and nothing else, and mononymous people exist — rejecting them here would be
     * a bug that only ever affects the people least able to work around it.
     */
    public boolean hasRequiredIdentityFields() {
        return isPresent(sessionId)
                && isPresent(surname)
                && isPresent(dateOfBirth)
                && isPresent(documentNumber)
                && isPresent(nationality)
                && isPresent(issuingState)
                && isPresent(dateOfExpiry);
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }
}
