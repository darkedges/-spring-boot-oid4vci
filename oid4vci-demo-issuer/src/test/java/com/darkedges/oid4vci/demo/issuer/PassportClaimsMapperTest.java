package com.darkedges.oid4vci.demo.issuer;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PassportClaimsMapperTest {

    private static final Clock IN_2026 = Clock.fixed(Instant.parse("2026-08-11T00:00:00Z"), ZoneOffset.UTC);

    private final PassportClaimsMapper mapper = new PassportClaimsMapper(IN_2026);

    private static ProofingResultRequest passing() {
        return new ProofingResultRequest(
                "session-1", "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, true, true, true, true);
    }

    @Test
    void mapsMrzFieldsOntoCredentialClaims() {
        Map<String, String> claims = mapper.toClaims(passing());

        assertThat(claims)
                .containsEntry("given_name", "ALEXANDRA JANE")
                .containsEntry("family_name", "FITZGERALD")
                .containsEntry("document_number", "PA1234567")
                .containsEntry("nationality", "GBR")
                .containsEntry("issuing_state", "GBR");
    }

    @Test
    void convertsMrzDatesToIso8601() {
        // The MRZ carries YYMMDD, which is not a date any Verifier can parse without knowing the
        // convention. A credential asserting birth_date=870314 asserts nothing usable.
        Map<String, String> claims = mapper.toClaims(passing());

        assertThat(claims).containsEntry("birth_date", "1987-03-14");
        assertThat(claims).containsEntry("expiry_date", "2031-06-12");
    }

    @Test
    void readsATwoDigitBirthYearAsThePastAndAnExpiryAsTheFuture() {
        // The same two digits mean different centuries in the two fields, and getting it wrong is
        // silent: "31" as a birth year is 1931, while "31" as an expiry is 2031. A single rule would
        // make one of the two absurd -- a passport that expired before powered flight, or a holder
        // not yet born.
        assertThat(mapper.toIsoDate("310612", false)).isEqualTo("1931-06-12");
        assertThat(mapper.toIsoDate("310612", true)).isEqualTo("2031-06-12");
    }

    @Test
    void readsAYearAtTheEdgeOfTheWindowAsThePast() {
        // Fixed clock is 2026, so "26" is this year and "27" cannot be a birth year yet.
        assertThat(mapper.toIsoDate("260101", false)).isEqualTo("2026-01-01");
        assertThat(mapper.toIsoDate("270101", false)).isEqualTo("1927-01-01");
    }

    @Test
    void leavesAnAlreadyIsoDateAlone() {
        // Idempotent, so a caller that has already normalised is not silently corrupted by a second
        // pass turning 1987-03-14 into nonsense.
        assertThat(mapper.toIsoDate("1987-03-14", false)).isEqualTo("1987-03-14");
    }

    @Test
    void rejectsADateThatIsNotRealRatherThanInventingOne() {
        // LocalDate would happily be asked for 31 February; refusing is better than issuing a
        // credential asserting a birth date that does not exist.
        assertThatThrownBy(() -> mapper.toIsoDate("870231", false)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> mapper.toIsoDate("not-a-date", false)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void alwaysStatesTheAssuranceLevelAndTheEvidence() {
        // The whole point of these two claims: this credential comes from a proof of concept with no
        // certified presentation-attack detection and an uncalibrated threshold. A Verifier that
        // cannot see that is being told something stronger than the evidence supports.
        Map<String, String> claims = mapper.toClaims(passing());

        assertThat(claims).containsEntry("assurance_level", "poc-demo");
        assertThat(claims.get("evidence")).contains("pad=none");
    }

    @Test
    void distinguishesACheckThatFailedFromOneThatNeverRan() {
        // null means not determined -- an absent CRL, a passport with no Active Authentication -- and
        // reporting that as "failed" would accuse a perfectly ordinary document of something.
        ProofingResultRequest notDetermined = new ProofingResultRequest(
                "session-1", "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, true, null, true, null);

        String evidence = mapper.toClaims(notDetermined).get("evidence");

        assertThat(evidence).contains("revocation=not-determined");
        assertThat(evidence).contains("active-auth=not-determined");
        assertThat(evidence).doesNotContain("revocation=failed");
    }

    @Test
    void reportsAFailedCheckAsFailed() {
        ProofingResultRequest revocationFailed = new ProofingResultRequest(
                "session-1", "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, true, false, true, true);

        assertThat(mapper.toClaims(revocationFailed).get("evidence")).contains("revocation=failed");
    }
}
