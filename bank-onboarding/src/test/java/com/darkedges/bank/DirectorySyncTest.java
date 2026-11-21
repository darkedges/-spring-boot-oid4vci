package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * The AuthStack directory: one AuthStack user per person (a chain of attempts), kept current from the outbox. Against a real PostgreSQL
 * database (BANK_TEST_DATABASE_URL, skipped without it) and a stand-in AuthStack. The pure rules are tested without either.
 */
class DirectorySyncTest {
    static final ObjectMapper JSON = new ObjectMapper();

    @Nested class Rules {
        @Test void operationsFollowTheLifecycle() {
            assertThat(StaffSnapshot.operations("ACTIVE")).containsExactly("revoke", "deactivate");
            assertThat(StaffSnapshot.operations("APPROVED")).containsExactly("revoke");
            assertThat(StaffSnapshot.operations("REVOKED")).containsExactly("reactivate");
            assertThat(StaffSnapshot.operations("INVITED")).isEmpty();
            assertThat(StaffSnapshot.operations("REVIEW")).isEmpty();
        }
        @Test void aCredentialFollowsItsAttempt() {
            assertThat(StaffSnapshot.credentialStatus("ACTIVE", false, false)).isEqualTo("SUPERSEDED");
            assertThat(StaffSnapshot.credentialStatus("ACTIVE", true, false)).isEqualTo("ACTIVE");
            assertThat(StaffSnapshot.credentialStatus("ACTIVE", true, true)).isEqualTo("EXPIRED");
            assertThat(StaffSnapshot.credentialStatus("REVOKED", true, false)).isEqualTo("REVOKED");
            assertThat(StaffSnapshot.credentialStatus("INACTIVE", true, false)).isEqualTo("INACTIVE");
        }
        @Test void onlyAnAdministratorOfTheBanksOrganizationMayAct() throws Exception {
            JsonNode admin = JSON.readTree("{\"user\":{\"role\":\"ORG_ADMIN\",\"email\":\"a@x\"},\"environments\":[{\"id\":\"env-bank\"}]}");
            assertThat(DirectoryActionsController.adminFrom(admin, "env-bank").email()).isEqualTo("a@x");
            assertThatThrownBy(() -> DirectoryActionsController.adminFrom(admin, "env-other")).hasMessageContaining("does not own");
            JsonNode viewer = JSON.readTree("{\"user\":{\"role\":\"ORG_VIEWER\"},\"environments\":[{\"id\":\"env-bank\"}]}");
            assertThatThrownBy(() -> DirectoryActionsController.adminFrom(viewer, "env-bank")).hasMessageContaining("administrator");
        }
    }

    @Nested class AgainstPostgres {
        @TempDir Path dir;
        JdbcTemplate db; BankController bank; DirectoryOutbox outbox; StaffSnapshot snapshots;
        HttpServer authstack; String authstackUrl;
        final List<String> calls = new CopyOnWriteArrayList<>();
        final Map<String, String> bodies = new HashMap<>();
        volatile int failWith = 0;

        @BeforeEach void setUp() throws Exception {
            String url = System.getenv("BANK_TEST_DATABASE_URL");
            Assumptions.assumeTrue(url != null && !url.isBlank(), "BANK_TEST_DATABASE_URL not set");
            db = new JdbcTemplate(new DriverManagerDataSource(url));
            db.execute("drop table if exists bank_directory_outbox, bank_applicant_ref, bank_presentation, bank_audit, bank_hire cascade");
            for (String statement : new String(getClass().getResourceAsStream("/schema.sql").readAllBytes()).split(";")) if (!statement.isBlank()) db.execute(statement);
            var key = new ECKeyGenerator(Curve.P_256).generate();
            var file = dir.resolve("passport.jwk"); Files.writeString(file, key.toPublicJWK().toJSONString());
            bank = new BankController(db, mock(PreAuthorizedCodeStore.class), key, "https://bank.example", "https://issuer.example", file.toString(), "Bank");
            outbox = new DirectoryOutbox(db);
            bank.setDirectory(outbox);
            snapshots = new StaffSnapshot(db);

            authstack = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            authstack.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                calls.add(exchange.getRequestMethod() + " " + path + " " + exchange.getRequestHeaders().getFirst("Authorization"));
                bodies.put(exchange.getRequestMethod() + " " + path, body);
                String answer = path.endsWith("/as/token") ? "{\"access_token\":\"worker-token\",\"expires_in\":3600}"
                    : path.endsWith("/users") ? "{\"id\":\"as-user-1\"}" : "{}";
                int status = failWith != 0 && !path.endsWith("/as/token") ? failWith : 200;
                byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            authstack.start();
            authstackUrl = "http://127.0.0.1:" + authstack.getAddress().getPort();
        }

        @AfterEach void tearDown() { if (authstack != null) authstack.stop(0); }

        AuthStackDirectory directory() {
            return new AuthStackDirectory(db, snapshots, authstackUrl + "/v1", authstackUrl + "/env-bank/as/token", "env-bank", "bank-directory", "secret", "pop-staff", "staff.bank.example", "https://bank.example");
        }

        UUID hire(String status, UUID previous) {
            UUID id = UUID.randomUUID();
            db.update("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,status,invite_hash,invite_expires,previous_hire_id) values (?,?,?,?,?,?,?,?,?,?)",
                id, "Ada", "Lovelace", LocalDate.of(1990, 1, 1), "ada@personal.example", "Risk", status, BankController.hash(id.toString()), Timestamp.from(Instant.now().plusSeconds(3600)), previous);
            return id;
        }

        @Test void aPersonIsTheirChainOfAttempts() {
            UUID first = hire("REVOKED", null), second = hire("REVOKED", first), third = hire("INVITED", second);
            assertThat(outbox.personOf(third)).isEqualTo(first);
            assertThat(outbox.personOf(first)).isEqualTo(first);
            assertThat(outbox.currentAttempt(first)).contains(third);
            assertThat(outbox.currentAttempt(second)).contains(third);
        }

        @Test void aChangeMarksThePersonOnceAndTheSyncCreatesAndKeepsTheirAuthStackUser() throws Exception {
            UUID first = hire("INVITED", null);
            outbox.changed(first);
            outbox.changed(first);
            assertThat(db.queryForObject("select count(*) from bank_directory_outbox", Integer.class)).isEqualTo(1);

            directory().syncDue();
            assertThat(calls).anyMatch(c -> c.startsWith("POST /env-bank/as/token"));
            assertThat(calls).contains("POST /v1/environments/env-bank/users Bearer worker-token",
                "PUT /v1/environments/env-bank/users/as-user-1/externalIdentities/risk-e-bank Bearer worker-token",
                "PUT /v1/environments/env-bank/users/as-user-1/enabled Bearer worker-token");
            JsonNode user = JSON.readTree(bodies.get("POST /v1/environments/env-bank/users"));
            assertThat(user.path("email").asText()).isEqualTo("staff-" + first + "@staff.bank.example");
            assertThat(user.path("externalId").asText()).isEqualTo(first.toString());
            assertThat(user.path("enabled").asBoolean()).isFalse();
            assertThat(user.path("population").path("id").asText()).isEqualTo("pop-staff");
            assertThat(bodies.get("POST /v1/environments/env-bank/users")).doesNotContain("ada@personal.example", "1990");
            JsonNode identity = JSON.readTree(bodies.get("PUT /v1/environments/env-bank/users/as-user-1/externalIdentities/risk-e-bank"));
            assertThat(identity.path("lifecycle").path("status").asText()).isEqualTo("INVITED");
            assertThat(identity.path("identity").path("status").asText()).isEqualTo("NOT_VERIFIED");
            assertThat(identity.path("actionsUrl").asText()).isEqualTo("https://bank.example/api/directory/v1/people/" + first + "/actions");
            assertThat(outbox.state(first)).containsEntry("state", "synced");
            assertThat(db.queryForObject("select authstack_user_id from bank_hire where id=?", String.class, first)).isEqualTo("as-user-1");

            // Nothing more to send until the next change.
            calls.clear();
            directory().syncDue();
            assertThat(calls).isEmpty();
        }

        @Test void reactivationKeepsOnePersonAndSupersedesTheOldCredential() throws Exception {
            UUID first = hire("ACTIVE", null);
            String credential = "eyJhbGciOiJFUzI1NiJ9." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"iat\":" + Instant.now().getEpochSecond() + ",\"exp\":" + Instant.now().plusSeconds(86400).getEpochSecond() + "}").getBytes()) + ".sig~disclosure~";
            db.update("update bank_hire set issued_credential=?, verified_given='Ada', verified_family='Lovelace' where id=?", credential, first);
            bank.applyDecision(first, "revoke", "Left the bank", "hr", null);
            var reactivated = bank.startReactivation(first, true, "admin@authstack (AuthStack console)", "authstack");
            UUID second = reactivated.attemptId();
            assertThat(reactivated.created()).isTrue();
            assertThat(outbox.personOf(second)).isEqualTo(first);
            assertThat(db.queryForObject("select channel from bank_audit where hire_id=? and action='VERIFICATION_REQUESTED'", String.class, second)).isEqualTo("authstack");

            var view = snapshots.build(first, "staff.bank.example", "https://bank.example");
            assertThat(view.enabled()).isFalse();
            @SuppressWarnings("unchecked") var lifecycle = (Map<String, Object>) view.identity().get("lifecycle");
            assertThat(lifecycle).containsEntry("status", "INVITED").containsEntry("attemptId", second.toString());
            @SuppressWarnings("unchecked") var credentials = (List<Map<String, Object>>) view.identity().get("credentials");
            assertThat(credentials).singleElement().satisfies(c -> assertThat(c).containsEntry("status", "SUPERSEDED").containsEntry("attemptId", first.toString()));
            assertThat(view.identity().get("operations")).isEqualTo(List.of());
            @SuppressWarnings("unchecked") var verification = (Map<String, Object>) view.identity().get("identity");
            assertThat(verification).containsEntry("freshProofingRequired", true);
            assertThat(JSON.writeValueAsString(view.identity())).doesNotContain(credential.split("~")[0], "ada@personal.example");
        }

        @Test void anActiveStaffMemberIsEnabledWithTheirCredentialActive() throws Exception {
            UUID first = hire("ACTIVE", null);
            db.update("update bank_hire set issued_credential=?, verified_given='Ada', verified_family='Lovelace' where id=?",
                "h." + Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"exp\":" + Instant.now().plusSeconds(86400).getEpochSecond() + "}").getBytes()) + ".s~", first);
            var view = snapshots.build(first, "staff.bank.example", "https://bank.example");
            assertThat(view.enabled()).isTrue();
            assertThat(view.identity().get("operations")).isEqualTo(List.of("revoke", "deactivate"));
            @SuppressWarnings("unchecked") var credentials = (List<Map<String, Object>>) view.identity().get("credentials");
            assertThat(credentials.getFirst()).containsEntry("status", "ACTIVE");
        }

        @Test void aFailedSyncIsRetriedLaterAndShownToHr() {
            UUID first = hire("INVITED", null);
            outbox.changed(first);
            failWith = 503;
            directory().syncDue();
            assertThat(outbox.state(first)).containsEntry("state", "failed");
            assertThat(db.queryForObject("select next_attempt_at > now() from bank_directory_outbox where person_id=?", Boolean.class, first)).isTrue();
            // Not due yet: nothing is sent until the backoff has passed.
            calls.clear();
            directory().syncDue();
            assertThat(calls).isEmpty();
            failWith = 0;
            db.update("update bank_directory_outbox set next_attempt_at=now() where person_id=?", first);
            directory().syncDue();
            assertThat(outbox.state(first)).containsEntry("state", "synced");
        }

        @Test void theConsoleCanRevokeButNotWhatTheCurrentStateDoesNotAllow() {
            UUID first = hire("ACTIVE", null);
            bank.applyDecision(first, "revoke", "Misconduct", "admin@x (AuthStack console)", "authstack");
            assertThat(db.queryForObject("select status from bank_hire where id=?", String.class, first)).isEqualTo("REVOKED");
            assertThat(db.queryForObject("select channel from bank_audit where hire_id=? and action='APPROVAL_REVOKED'", String.class, first)).isEqualTo("authstack");
            assertThatThrownBy(() -> bank.applyDecision(first, "deactivate", "", "admin@x (AuthStack console)", "authstack")).isInstanceOf(BankController.HireDecisionException.class);
            assertThat(outbox.state(first)).containsEntry("state", "pending");
        }
    }
}
