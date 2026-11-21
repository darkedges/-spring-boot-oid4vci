package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * Keeps each person's AuthStack user current (DirectoryOutbox says who changed). For each changed person it sends their whole current
 * state, built from the database now (StaffSnapshot):
 *   1. create or update the user: POST /v1/environments/{env}/users (an upsert by email): staff-<person id>@<domain>, externalId = person id;
 *   2. PUT  …/users/{id}/externalIdentities/risk-e-bank: the bank's view (lifecycle, identity, credentials, operations);
 *   3. PUT  …/users/{id}/enabled: only active staff may sign in.
 * With a client-credentials token of the bank's own worker application ("Risk E Bank directory"). A failure is retried with backoff and
 * shown on HR's card; it never affects what HR or the applicant are doing. Off while BANK_AUTHSTACK_API_URL is unset.
 */
@Component
public class AuthStackDirectory {
    private static final Logger LOG = LoggerFactory.getLogger(AuthStackDirectory.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    static final String ISSUER = "risk-e-bank";

    private final JdbcTemplate db;
    private final StaffSnapshot snapshots;
    private final RestClient http;
    private final String apiUrl, tokenUrl, environmentId, clientId, clientSecret, populationId, staffEmailDomain, actionsBase;
    private String token;
    private Instant tokenExpires = Instant.EPOCH;

    public AuthStackDirectory(JdbcTemplate db, StaffSnapshot snapshots,
            @Value("${bank.authstack.api-url:}") String apiUrl, @Value("${bank.authstack.token-url:}") String tokenUrl,
            @Value("${bank.authstack.environment-id:}") String environmentId, @Value("${bank.authstack.client-id:}") String clientId,
            @Value("${bank.authstack.client-secret:}") String clientSecret, @Value("${bank.authstack.population-id:}") String populationId,
            @Value("${bank.staff-email-domain:staff.bank.darkedges.com}") String staffEmailDomain, @Value("${bank.base-url}") String actionsBase) {
        this.db = db; this.snapshots = snapshots; this.http = RestClient.create();
        this.apiUrl = apiUrl.replaceAll("/+$", ""); this.tokenUrl = tokenUrl; this.environmentId = environmentId; this.clientId = clientId;
        this.clientSecret = clientSecret; this.populationId = populationId; this.staffEmailDomain = staffEmailDomain; this.actionsBase = actionsBase;
    }

    public boolean enabled() {
        return !apiUrl.isBlank() && !tokenUrl.isBlank() && !environmentId.isBlank() && !clientId.isBlank() && !clientSecret.isBlank();
    }

    @Scheduled(fixedDelayString = "${bank.authstack.sync-interval-ms:10000}", initialDelayString = "${bank.authstack.sync-initial-delay-ms:15000}")
    public void syncDue() {
        if (!enabled()) return;
        var due = db.queryForList("""
            select person_id from bank_directory_outbox
            where (synced_at is null or synced_at < changed_at) and next_attempt_at <= now()
            order by changed_at limit 25""", UUID.class);
        for (UUID person : due) sync(person);
    }

    /** Send one person now; records the outcome on their outbox row. */
    void sync(UUID personId) {
        // The state is read after this instant: a change made while sending leaves the person due again.
        Timestamp picked = db.queryForObject("select now()", Timestamp.class);
        try {
            var view = snapshots.build(personId, staffEmailDomain, actionsBase);
            String userId = upsertUser(view);
            call("PUT", "/environments/" + environmentId + "/users/" + userId + "/externalIdentities/" + ISSUER, view.identity());
            call("PUT", "/environments/" + environmentId + "/users/" + userId + "/enabled", Map.of("enabled", view.enabled()));
            db.update("update bank_hire set authstack_user_id=? where id=?", userId, personId);
            db.update("update bank_directory_outbox set synced_at=?, last_error=null, attempts=0 where person_id=?", picked, personId);
        } catch (Exception error) {
            String message = error instanceof RestClientResponseException http ? "AuthStack answered " + http.getStatusCode().value() : error.getClass().getSimpleName() + ": " + error.getMessage();
            LOG.warn("Could not bring person {}'s AuthStack user up to date: {}", personId, message);
            // Backoff: 30 s, 1, 2, 4 … minutes, at most an hour.
            db.update("""
                update bank_directory_outbox set attempts=attempts+1, last_error=?,
                  next_attempt_at=now() + make_interval(secs => least(3600, 30 * power(2, attempts))) where person_id=?""",
                message.length() > 300 ? message.substring(0, 300) : message, personId);
        }
    }

    private String upsertUser(StaffSnapshot.View view) throws Exception {
        var body = new LinkedHashMap<String, Object>();
        body.put("email", view.email());
        body.put("username", view.email());
        body.put("externalId", view.personId().toString());
        body.put("name", Map.of("given", Objects.toString(view.givenName(), ""), "family", Objects.toString(view.familyName(), "")));
        if (!populationId.isBlank()) body.put("population", Map.of("id", populationId));
        // Never enabled even for a moment before the PUT …/enabled below: a new hire cannot sign in.
        body.put("enabled", view.enabled());
        JsonNode created = call("POST", "/environments/" + environmentId + "/users", body);
        String id = created == null ? null : created.path("id").asText(null);
        if (id == null) throw new IllegalStateException("AuthStack returned no user id");
        return id;
    }

    private JsonNode call(String method, String path, Object body) throws Exception {
        String answer = http.method(org.springframework.http.HttpMethod.valueOf(method)).uri(apiUrl + path)
            .header("Authorization", "Bearer " + accessToken())
            .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON)
            .body(JSON.writeValueAsString(body))
            .retrieve().body(String.class);
        return answer == null || answer.isBlank() ? null : JSON.readTree(answer);
    }

    private synchronized String accessToken() throws Exception {
        if (token != null && Instant.now().isBefore(tokenExpires.minusSeconds(60))) return token;
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        String answer = http.post().uri(tokenUrl).header("Authorization", "Basic " + basic)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED).body("grant_type=client_credentials")
            .retrieve().body(String.class);
        JsonNode body = JSON.readTree(answer);
        token = body.path("access_token").asText();
        tokenExpires = Instant.now().plusSeconds(body.path("expires_in").asLong(300));
        return token;
    }
}
