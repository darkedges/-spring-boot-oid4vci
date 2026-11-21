package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The operations the AuthStack console offers on a staff member's page (revoke, deactivate, reactivate), relayed by AuthStack on behalf of
 * the administrator who chose them (AuthStack routes/v1/userExternalIdentities.ts).
 *
 *   POST /api/directory/v1/people/{personId}/actions   { action: revoke|deactivate|reactivate, reason?, forcePassportCheck? }
 *
 * The caller is that administrator's own one-hour AuthStack console token. The bank checks it with AuthStack (GET /api/auth/me): an
 * ADMIN or ORG_ADMIN whose organization owns the bank's environment. The bank then applies the action with its own rules, the same ones
 * HR's page uses (BankController.applyDecision / startReactivation): same locks, same preconditions, same audit, with the administrator
 * as the actor and "authstack" as the channel. Approving and rejecting stay with HR.
 */
@RestController
@RequestMapping(value = "/api/directory/v1", produces = "application/json")
public class DirectoryActionsController {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final BankController bank;
    private final DirectoryOutbox outbox;
    private final RestClient http = RestClient.create();
    private final String meUrl, environmentId;
    private final Map<String, Map.Entry<Admin, Instant>> checked = new ConcurrentHashMap<>();

    public DirectoryActionsController(BankController bank, DirectoryOutbox outbox,
            @Value("${bank.authstack.console-me-url:}") String meUrl, @Value("${bank.authstack.environment-id:}") String environmentId) {
        this.bank = bank; this.outbox = outbox; this.meUrl = meUrl; this.environmentId = environmentId;
    }

    record Admin(String email, String role) {}
    record Action(String action, String reason, Boolean forcePassportCheck) {}

    static final class Refusal extends RuntimeException {
        final HttpStatus status; final String code;
        Refusal(HttpStatus status, String code, String message) { super(message, null, false, false); this.status = status; this.code = code; }
    }
    @ExceptionHandler(Refusal.class)
    ResponseEntity<Map<String, String>> refused(Refusal refusal) {
        return ResponseEntity.status(refusal.status).body(Map.of("code", refusal.code, "message", Objects.toString(refusal.getMessage(), "")));
    }
    @ExceptionHandler(BankController.HireDecisionException.class)
    ResponseEntity<Map<String, String>> notNow(BankController.HireDecisionException error) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "NOT_ALLOWED_NOW", "message", Objects.toString(error.getReason(), "")));
    }

    @PostMapping("/people/{personId}/actions")
    Map<String, Object> act(@PathVariable UUID personId, @RequestHeader(value = "Authorization", required = false) String authorization, @RequestBody Action body) {
        Admin admin = administrator(authorization);
        if (!personId.equals(outbox.personOf(personId))) throw new Refusal(HttpStatus.NOT_FOUND, "NOT_FOUND", "No such person");
        UUID current = outbox.currentAttempt(personId).orElseThrow(() -> new Refusal(HttpStatus.NOT_FOUND, "NOT_FOUND", "No such person"));
        String actor = admin.email() + " (AuthStack console)";
        String reason = body == null || body.reason() == null ? "" : body.reason().trim();
        String action = body == null ? "" : Objects.toString(body.action(), "");
        switch (action) {
            case "revoke", "deactivate" -> bank.applyDecision(current, action, reason, actor, "authstack");
            case "reactivate" -> bank.startReactivation(current, body.forcePassportCheck() == Boolean.TRUE, actor, "authstack");
            default -> throw new Refusal(HttpStatus.BAD_REQUEST, "UNKNOWN_ACTION", "Unknown action");
        }
        UUID now = outbox.currentAttempt(personId).orElse(current);
        return Map.of("personId", personId.toString(), "attemptId", now.toString(), "action", action);
    }

    /** The administrator behind this console token, or a refusal. AuthStack's answer is kept for 30 seconds, by the token's digest. */
    Admin administrator(String authorization) {
        if (meUrl.isBlank() || environmentId.isBlank()) throw new Refusal(HttpStatus.SERVICE_UNAVAILABLE, "NOT_CONFIGURED", "The bank is not connected to AuthStack");
        if (authorization == null || !authorization.startsWith("Bearer ")) throw new Refusal(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Sign in with your AuthStack account");
        String token = authorization.substring("Bearer ".length());
        String key = digest(token);
        var hit = checked.get(key);
        if (hit != null && hit.getValue().isAfter(Instant.now())) return hit.getKey();
        JsonNode me;
        try {
            me = JSON.readTree(http.get().uri(meUrl).header("Authorization", "Bearer " + token).retrieve().body(String.class));
        } catch (RestClientResponseException refused) {
            throw new Refusal(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "AuthStack did not accept this sign-in");
        } catch (Exception unreachable) {
            throw new Refusal(HttpStatus.SERVICE_UNAVAILABLE, "AUTHSTACK_UNAVAILABLE", "AuthStack could not check this sign-in");
        }
        Admin admin = adminFrom(me, environmentId);
        checked.put(key, Map.entry(admin, Instant.now().plusSeconds(30)));
        return admin;
    }

    /** Pure: may this AuthStack account change the bank's staff? An ADMIN or ORG_ADMIN whose organization owns the bank's environment. */
    static Admin adminFrom(JsonNode me, String environmentId) {
        String role = me.path("user").path("role").asText("");
        String email = me.path("user").path("email").asText("an administrator");
        if (!Set.of("ADMIN", "ORG_ADMIN").contains(role)) throw new Refusal(HttpStatus.FORBIDDEN, "NOT_AN_ADMINISTRATOR", "Only an organization administrator can change staff access");
        boolean owns = false;
        for (JsonNode environment : me.path("environments")) owns |= environmentId.equals(environment.path("id").asText());
        if (!owns) throw new Refusal(HttpStatus.FORBIDDEN, "NOT_THIS_ORGANIZATION", "This account's organization does not own the bank's environment");
        return new Admin(email, role);
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
