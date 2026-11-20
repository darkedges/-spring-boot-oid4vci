package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.jwt.Jwt;
import java.nio.file.*;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * The Journey API against a real PostgreSQL database (BANK_TEST_DATABASE_URL, e.g. jdbc:postgresql://localhost:15433/bank?user=bank&password=bank;
 * skipped without it), so the SQL, the row locks and the schema additions are exercised for real. The token rules are tested without one.
 */
class JourneyApiTest {
    static final String BASE = "https://hr.bank.example";

    @Nested class TokenRules {
        Jwt token(Map<String, Object> claims) {
            var builder = Jwt.withTokenValue("t").header("alg", "ES256").issuer("https://as.example/env").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
            claims.forEach(builder::claim);
            return builder.build();
        }
        final org.springframework.security.oauth2.core.OAuth2TokenValidator<Jwt> rules = BankSecurity.journeyClaims("bank-journey", "bank.journey", "authr, other");

        @Test void acceptsTheAudienceScopeAndAnAllowedClient() {
            assertThat(rules.validate(token(Map.of("aud", List.of("bank-journey"), "scope", "openid bank.journey", "client_id", "authr"))).hasErrors()).isFalse();
        }
        @Test void refusesATokenForAnotherApiOrClientOrWithoutTheScope() {
            assertThat(rules.validate(token(Map.of("aud", List.of("another-api"), "scope", "bank.journey", "client_id", "authr"))).hasErrors()).isTrue();
            assertThat(rules.validate(token(Map.of("aud", List.of("bank-journey"), "scope", "bank.journey.read", "client_id", "authr"))).hasErrors()).isTrue();
            assertThat(rules.validate(token(Map.of("aud", List.of("bank-journey"), "scope", "bank.journey", "client_id", "someone"))).hasErrors()).isTrue();
            assertThat(rules.validate(token(Map.of("aud", List.of("bank-journey"), "scope", "bank.journey"))).hasErrors()).isTrue();
        }
        @Test void anEmptyClientListAllowsNobody() {
            var none = BankSecurity.journeyClaims("bank-journey", "bank.journey", "");
            assertThat(none.validate(token(Map.of("aud", List.of("bank-journey"), "scope", "bank.journey", "client_id", ""))).hasErrors()).isTrue();
        }
    }

    @Nested class AgainstPostgres {
        @TempDir Path dir;
        JdbcTemplate db; BankController bank; JourneyApiController api;

        @BeforeEach void setUp() throws Exception {
            String url = System.getenv("BANK_TEST_DATABASE_URL");
            Assumptions.assumeTrue(url != null && !url.isBlank(), "BANK_TEST_DATABASE_URL not set");
            db = new JdbcTemplate(new DriverManagerDataSource(url));
            db.execute("drop table if exists bank_applicant_ref, bank_presentation, bank_audit, bank_hire cascade");
            for (String statement : new String(getClass().getResourceAsStream("/schema.sql").readAllBytes()).split(";")) if (!statement.isBlank()) db.execute(statement);
            var key = new ECKeyGenerator(Curve.P_256).generate();
            var file = dir.resolve("passport.jwk"); Files.writeString(file, key.toPublicJWK().toJSONString());
            bank = new BankController(db, mock(PreAuthorizedCodeStore.class), key, BASE, "https://issuer.example", file.toString(), "Bank");
            api = new JourneyApiController(db, bank, 2);
        }

        String hire(String invite, String status, Instant inviteExpires) {
            UUID id = UUID.randomUUID();
            db.update("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,status,invite_hash,invite_expires,holder_jwk,verified_given,verified_family) values (?,?,?,?,?,?,?,?,?,?,?,?)",
                id, "Ada", "Lovelace", LocalDate.of(1990, 1, 1), "ada@example.test", "Risk", status, BankController.hash(invite), Timestamp.from(inviteExpires),
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\"}", "Ada", "Lovelace");
            return id.toString();
        }
        void offer(String ref) { try { api.offer(ref); } catch (RuntimeException e) { throw e; } catch (Exception e) { throw new IllegalStateException(e); } }
        void walletCompletes(String presentationId, UUID staff) { db.update("update bank_presentation set complete=true, staff_id=? where id=?", staff, presentationId); }
        String code(Runnable call) {
            try { call.run(); return "none"; } catch (JourneyApiController.JourneyRefusal refusal) { return refusal.status.value() + " " + refusal.code; }
        }

        @Test void anApplicantRedeemsPresentsAndTheResultCanBeTakenOnceWithItsSecret() {
            hire("invite-1", "INVITED", Instant.now().plusSeconds(3600));
            var redeemed = api.redeem(new JourneyApiController.Redeem("invite-1"));
            String ref = (String) redeemed.get("applicantRef");
            assertThat(redeemed.get("stage")).isEqualTo("present");
            assertThat(db.queryForObject("select count(*) from bank_applicant_ref where ref_hash=?", Integer.class, ref)).isZero(); // only the hash is kept

            var started = api.startPassportPresentation(ref);
            String id = (String) started.get("presentationId"), secret = (String) started.get("completionSecret");
            assertThat((String) started.get("walletUri")).startsWith("openid4vp://?request_uri=").contains(java.net.URLEncoder.encode(BASE + "/vp/request/" + id, java.nio.charset.StandardCharsets.UTF_8));
            assertThat(api.presentation(id, secret)).containsEntry("status", "pending");
            assertThat(code(() -> api.consume(id, secret))).isEqualTo("409 not_complete");

            walletCompletes(id, null);
            db.update("update bank_hire set status='REVIEW'");
            assertThat(api.presentation(id, secret)).containsEntry("status", "complete");
            assertThat(code(() -> api.presentation(id, "someone-elses-secret"))).isEqualTo("404 unknown_presentation");
            assertThat(api.consume(id, secret)).containsEntry("stage", "in_review");
            assertThat(code(() -> api.consume(id, secret))).isEqualTo("409 already_consumed");
            assertThat(db.queryForList("select action, channel from bank_audit order by id")).extracting(r -> r.get("action") + "/" + r.get("channel")).contains("INVITE_OPENED/authr");
        }

        @Test void invitationsThatAreUnknownExpiredOrClosedAreRefusedDistinctly() {
            hire("expired", "INVITED", Instant.now().minusSeconds(1));
            hire("rejected", "REJECTED", Instant.now().plusSeconds(3600));
            assertThat(code(() -> api.redeem(new JourneyApiController.Redeem("nope")))).isEqualTo("404 invalid_invitation");
            assertThat(code(() -> api.redeem(new JourneyApiController.Redeem("expired")))).isEqualTo("410 invitation_expired");
            assertThat(code(() -> api.redeem(new JourneyApiController.Redeem("rejected")))).isEqualTo("409 invitation_closed");
        }

        @Test void aNewRedeemReplacesTheEarlierReferenceAndReferencesExpire() {
            hire("invite-2", "INVITED", Instant.now().plusSeconds(3600));
            String first = (String) api.redeem(new JourneyApiController.Redeem("invite-2")).get("applicantRef");
            String second = (String) api.redeem(new JourneyApiController.Redeem("invite-2")).get("applicantRef");
            assertThat(code(() -> api.applicant(first))).isEqualTo("404 unknown_applicant");
            assertThat(api.applicant(second)).containsEntry("stage", "present");
            db.update("update bank_applicant_ref set expires_at=now() - interval '1 second'");
            assertThat(code(() -> api.applicant(second))).isEqualTo("404 unknown_applicant");
        }

        @Test void aPresentationCanOnlyStartWhileAwaitingIdentityAndAnOfferOnlyOnceApproved() throws Exception {
            String id = hire("invite-3", "REVIEW", Instant.now().plusSeconds(3600));
            String ref = (String) api.redeem(new JourneyApiController.Redeem("invite-3")).get("applicantRef");
            assertThat(code(() -> api.startPassportPresentation(ref))).isEqualTo("409 wrong_stage");
            assertThat(code(() -> offer(ref))).isEqualTo("409 wrong_stage");

            db.update("update bank_hire set status='APPROVED' where id=?", UUID.fromString(id));
            assertThat(api.applicant(ref)).containsEntry("stage", "collect");
            assertThat((String) api.offer(ref).get("offerUri")).startsWith("openid-credential-offer://?credential_offer=");

            db.update("update bank_hire set status='REVOKED' where id=?", UUID.fromString(id));
            assertThat(api.applicant(ref)).containsEntry("stage", "closed");
            assertThat(code(() -> offer(ref))).isEqualTo("409 wrong_stage");
        }

        @Test void aNewerAttemptClosesTheOldOne() {
            String old = hire("invite-4", "REVOKED", Instant.now().plusSeconds(3600));
            db.update("update bank_hire set status='APPROVED' where id=?", UUID.fromString(old));
            String ref = (String) api.redeem(new JourneyApiController.Redeem("invite-4")).get("applicantRef");
            UUID next = UUID.fromString(hire("invite-5", "INVITED", Instant.now().plusSeconds(3600)));
            db.update("update bank_hire set previous_hire_id=? where id=?", UUID.fromString(old), next);
            assertThat(api.applicant(ref)).containsEntry("stage", "closed");
            assertThat(code(() -> api.redeem(new JourneyApiController.Redeem("invite-4")))).isEqualTo("409 invitation_closed");
        }

        @Test void staffSignInIsRateLimitedAndRefusedOnceApprovalIsRevoked() {
            UUID staff = UUID.fromString(hire("invite-6", "ACTIVE", Instant.now().plusSeconds(3600)));
            var caller = Jwt.withTokenValue("t").header("alg", "ES256").claim("client_id", "authr").build();
            var started = api.startStaffPresentation(caller);
            api.startStaffPresentation(caller);
            assertThat(code(() -> api.startStaffPresentation(caller))).isEqualTo("429 rate_limited");

            String id = (String) started.get("presentationId"), secret = (String) started.get("completionSecret");
            walletCompletes(id, staff);
            db.update("update bank_hire set status='REVOKED' where id=?", staff);
            assertThat(code(() -> api.consume(id, secret))).isEqualTo("409 staff_inactive");
        }

        @Test void anActiveStaffMemberIsNamedOnlyThroughConsume() {
            UUID staff = UUID.fromString(hire("invite-7", "ACTIVE", Instant.now().plusSeconds(3600)));
            var started = api.startStaffPresentation(Jwt.withTokenValue("t").header("alg", "ES256").claim("client_id", "authr").build());
            String id = (String) started.get("presentationId"), secret = (String) started.get("completionSecret");
            walletCompletes(id, staff);
            assertThat(api.presentation(id, secret)).isEqualTo(Map.of("status", "complete"));
            assertThat(api.consume(id, secret)).isEqualTo(Map.of("staffSubject", staff.toString()));
        }

        @Test void aPortalPresentationIsInvisibleToTheApiAndExpiryWins() {
            hire("invite-8", "INVITED", Instant.now().plusSeconds(3600));
            UUID hire = db.queryForObject("select id from bank_hire", UUID.class);
            var portal = bank.newPresentation(hire, "portal");
            assertThat(code(() -> api.presentation(portal.id(), portal.secret()))).isEqualTo("404 unknown_presentation");

            String ref = (String) api.redeem(new JourneyApiController.Redeem("invite-8")).get("applicantRef");
            var started = api.startPassportPresentation(ref);
            String id = (String) started.get("presentationId"), secret = (String) started.get("completionSecret");
            walletCompletes(id, null);
            db.update("update bank_presentation set expires_at=now() - interval '1 second' where id=?", id);
            assertThat(api.presentation(id, secret)).containsEntry("status", "expired");
            assertThat(code(() -> api.consume(id, secret))).isEqualTo("409 expired");
        }
    }
}
