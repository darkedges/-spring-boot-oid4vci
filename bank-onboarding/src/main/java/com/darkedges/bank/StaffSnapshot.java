package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * What the bank tells AuthStack about one person: their AuthStack user (name, whether they may sign in) and the bank's view of them,
 * stored on that user as the "risk-e-bank" external identity. Built from the database, so it is always the whole current state.
 *
 * Nothing secret leaves the bank: no credential (only a digest of it to tell credentials apart), no birth date, no personal email,
 * no invitation.
 */
@Component
public class StaffSnapshot {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final JdbcTemplate db;

    public StaffSnapshot(JdbcTemplate db) { this.db = db; }

    /** The person's AuthStack user and external identity. */
    public record View(UUID personId, String email, String givenName, String familyName, boolean enabled, Map<String, Object> identity) {}

    public View build(UUID personId, String staffEmailDomain, String actionsBase) {
        var attempts = db.queryForList("""
            with recursive down as (select h.*, 1 as n from bank_hire h where h.id=?
              union all select h.*, down.n+1 from bank_hire h join down on h.previous_hire_id=down.id)
            select * from down order by n""", personId);
        if (attempts.isEmpty()) throw new IllegalArgumentException("No such person: " + personId);
        var current = attempts.getLast();
        UUID currentId = (UUID) current.get("id");
        String status = (String) current.get("status");
        boolean verified = current.get("verified_family") != null;
        // HR's recruitment names until the Passport-verified names have been approved.
        boolean approvedIdentity = Set.of("APPROVED", "ACTIVE", "INACTIVE", "REVOKED").contains(status) && verified;
        String given = (String) (approvedIdentity ? current.get("verified_given") : current.get("expected_given"));
        String family = (String) (approvedIdentity ? current.get("verified_family") : current.get("expected_family"));

        var identity = new LinkedHashMap<String, Object>();
        identity.put("issuerName", "Risk E Bank");
        identity.put("actionsUrl", actionsBase + "/api/directory/v1/people/" + personId + "/actions");
        var lifecycle = new LinkedHashMap<String, Object>();
        lifecycle.put("status", status);
        Object reason = "REVOKED".equals(status) ? current.get("revocation_reason") : current.get("decision_reason");
        if (reason instanceof String text && !text.isBlank()) lifecycle.put("reason", text);
        lifecycle.put("updatedAt", latest(current, "revoked_at", "reviewed_at", "created_at"));
        lifecycle.put("attemptId", currentId.toString());
        lifecycle.put("department", current.get("department"));
        identity.put("lifecycle", lifecycle);

        var verification = new LinkedHashMap<String, Object>();
        verification.put("status", verified ? "VERIFIED" : "NOT_VERIFIED");
        verification.put("method", "Passport credential (OID4VP)");
        auditTime(currentId, "IDENTITY_PRESENTED").ifPresent(at -> verification.put("verifiedAt", at));
        verification.put("freshProofingRequired", current.get("passport_check_after") != null);
        identity.put("identity", verification);

        var history = new ArrayList<Map<String, Object>>();
        var credentials = new ArrayList<Map<String, Object>>();
        for (var attempt : attempts) {
            UUID id = (UUID) attempt.get("id");
            var item = new LinkedHashMap<String, Object>();
            item.put("id", id.toString());
            item.put("status", attempt.get("status"));
            item.put("createdAt", iso(attempt.get("created_at")));
            if (attempt.get("reviewed_at") != null) item.put("reviewedAt", iso(attempt.get("reviewed_at")));
            if (attempt.get("reviewer") != null) item.put("reviewer", attempt.get("reviewer"));
            if (attempt.get("revoked_at") != null) item.put("revokedAt", iso(attempt.get("revoked_at")));
            history.add(item);
            if (attempt.get("issued_credential") instanceof String issued) credentials.add(credential(issued, attempt, id.equals(currentId)));
        }
        identity.put("attempts", history);
        identity.put("credentials", credentials);
        identity.put("operations", operations(status));
        lastSignIn(attempts).ifPresent(at -> identity.put("lastSignInAt", at));

        return new View(personId, "staff-" + personId + "@" + staffEmailDomain, given, family, "ACTIVE".equals(status), identity);
    }

    /** What an administrator may ask the bank to do for this person now (DirectoryActionsController enforces the same). */
    static List<String> operations(String status) {
        return switch (status) {
            case "ACTIVE" -> List.of("revoke", "deactivate");
            case "APPROVED" -> List.of("revoke");
            case "REVOKED", "INACTIVE", "CANCELLED", "REJECTED" -> List.of("reactivate");
            default -> List.of();
        };
    }

    private Map<String, Object> credential(String issued, Map<String, Object> attempt, boolean current) {
        String issuerJwt = issued.split("~", 2)[0];
        var out = new LinkedHashMap<String, Object>();
        out.put("id", sha256(issuerJwt).substring(0, 16));
        out.put("type", "BankStaffCredential");
        out.put("format", "dc+sd-jwt");
        out.put("attemptId", attempt.get("id").toString());
        try {
            JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(issuerJwt.split("\\.")[1]));
            if (claims.has("iat")) out.put("issuedAt", Instant.ofEpochSecond(claims.get("iat").asLong()).toString());
            if (claims.has("exp")) out.put("expiresAt", Instant.ofEpochSecond(claims.get("exp").asLong()).toString());
            JsonNode jwk = claims.path("cnf").path("jwk");
            if (!jwk.isMissingNode()) out.put("holderKeyThumbprint", JWK.parse(jwk.toString()).computeThumbprint().toString());
            boolean expired = claims.has("exp") && Instant.ofEpochSecond(claims.get("exp").asLong()).isBefore(Instant.now());
            out.put("status", credentialStatus((String) attempt.get("status"), current, expired));
        } catch (Exception unreadable) {
            out.put("status", credentialStatus((String) attempt.get("status"), current, false));
        }
        return out;
    }

    /** A credential of an earlier attempt is superseded; the current attempt's follows the attempt (and its own expiry). */
    static String credentialStatus(String attemptStatus, boolean currentAttempt, boolean expired) {
        if (!currentAttempt) return "SUPERSEDED";
        return switch (attemptStatus) {
            case "REVOKED" -> "REVOKED";
            case "INACTIVE" -> "INACTIVE";
            case "ACTIVE", "APPROVED" -> expired ? "EXPIRED" : "ACTIVE";
            default -> "INACTIVE";
        };
    }

    private Optional<String> auditTime(UUID hireId, String action) {
        var rows = db.queryForList("select max(occurred_at) as at from bank_audit where hire_id=? and action=?", hireId, action);
        return rows.isEmpty() || rows.getFirst().get("at") == null ? Optional.empty() : Optional.of(iso(rows.getFirst().get("at")));
    }

    private Optional<String> lastSignIn(List<Map<String, Object>> attempts) {
        var ids = attempts.stream().map(a -> a.get("id")).toArray();
        String marks = String.join(",", Collections.nCopies(ids.length, "?"));
        var rows = db.queryForList("select max(occurred_at) as at from bank_audit where action='STAFF_SIGN_IN' and hire_id in (" + marks + ")", ids);
        return rows.isEmpty() || rows.getFirst().get("at") == null ? Optional.empty() : Optional.of(iso(rows.getFirst().get("at")));
    }

    private static String latest(Map<String, Object> row, String... columns) {
        return Arrays.stream(columns).map(row::get).filter(Objects::nonNull).map(v -> ((Timestamp) v).toInstant()).max(Comparator.naturalOrder())
            .map(Instant::toString).orElse(null);
    }

    private static String iso(Object timestamp) {
        return timestamp instanceof Timestamp t ? t.toInstant().toString() : String.valueOf(timestamp);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
