package com.darkedges.oid4vci.demo.issuer;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns a verified proofing result into the claim values a {@code PassportCredential} asserts.
 *
 * <p>Every value is a {@code String} because that is what {@code PreAuthorizedCodeSession#claims},
 * {@code IssuedAccessTokenClaimsStore} and {@code SdJwtVcCredentialIssuanceService} all carry. The
 * DG2 portrait itself is deliberately absent: as an image it would have to be base64 inside one of
 * those strings, bloating every credential and every presentation that discloses it, and widening the
 * claim type across five classes is a decision to take on its own rather than as a side effect.
 *
 * <p>What is carried instead is a <em>face template</em> — a 512-float ArcFace embedding, about 2.7KB
 * base64, and still the largest claim here by a wide margin. It is not a photograph and cannot be
 * rendered as one, which is what makes it issuable: a wallet compares a live selfie against it on the
 * device, and no verifier receives the holder's picture. It remains biometric data about a specific
 * person, so it is one disclosure among several rather than part of the always-visible payload.
 *
 * <p>{@code assurance_level} and {@code evidence} exist so a Verifier is told what this credential is
 * <em>not</em>. It is issued from a proof of concept with no certified presentation-attack detection
 * and an uncalibrated face-match threshold; a credential that asserted an identity while staying
 * silent about that would be making a stronger claim than the evidence supports.
 */
public final class PassportClaimsMapper {

    /** Kept in step with {@code face_template.TEMPLATE_FORMAT} in the proofing service. */
    static final String FACE_TEMPLATE_FORMAT = "arcface-buffalo_l-512-f32";

    private final Clock clock;

    public PassportClaimsMapper(Clock clock) {
        this.clock = clock;
    }

    public Map<String, String> toClaims(ProofingResultRequest result) {
        Map<String, String> claims = new LinkedHashMap<>();
        claims.put("given_name", result.givenNames());
        claims.put("family_name", result.surname());
        claims.put("birth_date", toIsoDate(result.dateOfBirth(), false));
        claims.put("document_number", result.documentNumber());
        claims.put("nationality", result.nationality());
        claims.put("issuing_state", result.issuingState());
        claims.put("expiry_date", toIsoDate(result.dateOfExpiry(), true));
        // Only when one was produced. An absent template is an ordinary outcome, and a claim
        // present-but-empty would be worse than missing: a verifier would try to match against it.
        if (result.faceTemplate() != null && !result.faceTemplate().isBlank()) {
            claims.put("face_template", result.faceTemplate());
            // Names the model and layout the template came from. A verifier that does not recognise
            // this must refuse to compare rather than guess -- a cosine score between embeddings
            // from two different models is a meaningless number that looks exactly like a real one.
            claims.put("face_template_format", FACE_TEMPLATE_FORMAT);
        }
        claims.put("assurance_level", "poc-demo");
        claims.put("evidence", describeEvidence(result));
        return Map.copyOf(claims);
    }

    /**
     * A one-line summary of what was actually established about the document.
     *
     * <p>Assembled from the server's own findings rather than a fixed string, so a credential issued
     * from a chip whose revocation status was never checked does not read the same as one where it
     * was. The proofing service reports each check separately for that reason, and flattening them
     * into "verified" here would throw away the distinction it went to the trouble of preserving.
     */
    private static String describeEvidence(ProofingResultRequest result) {
        StringBuilder evidence = new StringBuilder("liveness=")
                .append(result.livenessPassed() ? "passed" : "not-passed")
                .append("; face-match=")
                .append(result.faceMatched() ? "passed" : "not-passed");
        evidence.append("; chip-signature=").append(describe(result.sodSignatureValid()));
        evidence.append("; csca-chain=").append(describe(result.cscaValidated()));
        evidence.append("; revocation=").append(describe(result.revocationChecked()));
        evidence.append("; portrait-from-chip=").append(describe(result.portraitFromChip()));
        evidence.append("; active-auth=").append(describe(result.activeAuthenticationValid()));
        evidence.append("; pad=none");
        return evidence.toString();
    }

    /** {@code null} is "not determined", which is not the same fact as "checked and failed". */
    private static String describe(Boolean value) {
        if (value == null) {
            return "not-determined";
        }
        return value ? "verified" : "failed";
    }

    /**
     * MRZ {@code YYMMDD} to ISO 8601 {@code YYYY-MM-DD}.
     *
     * <p>The MRZ carries no century, so one has to be inferred, and the right inference differs by
     * field. A date of birth is always in the past, so a two-digit year above the current one must
     * belong to the previous century — the sliding window ICAO 9303 Part 3 describes. An expiry date
     * is the opposite: a passport does not expire before it was issued, so {@code 20YY} is the only
     * sensible reading, and the same sliding window would misread a 2031 expiry as 1931.
     *
     * <p>Passed through unchanged if it already looks like an ISO date, so a caller that has already
     * normalised is not corrupted by a second conversion.
     */
    String toIsoDate(String mrzDate, boolean future) {
        if (mrzDate == null || mrzDate.isBlank()) {
            return "";
        }
        String trimmed = mrzDate.trim();
        if (trimmed.matches("\\d{4}-\\d{2}-\\d{2}")) {
            return trimmed;
        }
        if (!trimmed.matches("\\d{6}")) {
            throw new IllegalArgumentException("expected an MRZ YYMMDD date");
        }

        int yy = Integer.parseInt(trimmed.substring(0, 2));
        int month = Integer.parseInt(trimmed.substring(2, 4));
        int day = Integer.parseInt(trimmed.substring(4, 6));

        int currentYear = LocalDate.now(clock).getYear();
        int century = (currentYear / 100) * 100;
        int year;
        if (future) {
            year = century + yy;
        } else {
            year = century + yy;
            if (year > currentYear) {
                year -= 100;
            }
        }

        try {
            return LocalDate.of(year, month, day).toString();
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("MRZ date is not a real date: " + trimmed, e);
        }
    }
}
