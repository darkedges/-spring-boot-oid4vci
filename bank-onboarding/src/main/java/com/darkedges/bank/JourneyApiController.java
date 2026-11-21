package com.darkedges.bank;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Journey API: the applicant and staff journeys for a front end that is not this portal (Authr). The caller is a machine client
 * (BankSecurity.journey: an AuthStack client-credentials token with this API's audience and scope, from an allowed client), never a
 * person, and nothing it asserts is taken on trust: every decision (is this invitation valid, may a presentation start, has the wallet
 * completed, is this staff member active) is made here, from this database, exactly as the portal makes it.
 *
 * Opaque references only: an opened invitation becomes a short-lived applicant reference (only its hash is stored); a presentation's
 * result is readable only with the completion secret returned when it was started, and can be taken once.
 */
@RestController
@RequestMapping(value = "/api/journey/v1", produces = "application/json")
public class JourneyApiController {
    static final Duration REF_LIFETIME = Duration.ofMinutes(30);
    private final JdbcTemplate db;
    private final BankController bank;
    private final int staffStartsPerMinute;
    private final Map<String, Deque<Instant>> staffStarts = new ConcurrentHashMap<>();

    private DirectoryOutbox directory;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setDirectory(DirectoryOutbox directory) { this.directory = directory; }

    public JourneyApiController(JdbcTemplate db, BankController bank, @Value("${bank.journey.staff-sign-in-per-minute:60}") int staffStartsPerMinute) {
        this.db = db; this.bank = bank; this.staffStartsPerMinute = staffStartsPerMinute;
    }

    /** A refusal the caller can route on: a stable code, never personal data. */
    static final class JourneyRefusal extends RuntimeException {
        final HttpStatus status; final String code;
        JourneyRefusal(HttpStatus status, String code) { super(code, null, false, false); this.status = status; this.code = code; }
    }
    @ExceptionHandler(JourneyRefusal.class)
    ResponseEntity<Map<String, String>> refused(JourneyRefusal refusal) { return ResponseEntity.status(refusal.status).body(Map.of("code", refusal.code)); }

    record Redeem(String inviteToken) {}

    // ── Applicant ────────────────────────────────────────────────────────────────────────────────────────────────────────────

    @PostMapping("/invitations/redeem") @Transactional
    Map<String, Object> redeem(@RequestBody Redeem body) {
        if (body == null || body.inviteToken() == null || body.inviteToken().isBlank()) throw new JourneyRefusal(HttpStatus.NOT_FOUND, "invalid_invitation");
        var rows = db.queryForList("select id, status, invite_expires from bank_hire where invite_hash=?", BankController.hash(body.inviteToken()));
        if (rows.size() != 1) throw new JourneyRefusal(HttpStatus.NOT_FOUND, "invalid_invitation");
        var hire = rows.getFirst();
        UUID id = (UUID) hire.get("id");
        if (!((java.sql.Timestamp) hire.get("invite_expires")).toInstant().isAfter(Instant.now())) throw new JourneyRefusal(HttpStatus.GONE, "invitation_expired");
        // The same rule as the portal's /invite/{token}.
        if (Set.of("CANCELLED", "REJECTED", "INACTIVE", "REVOKED").contains(hire.get("status")) || superseded(id)) throw new JourneyRefusal(HttpStatus.CONFLICT, "invitation_closed");
        String ref = BankController.token();
        db.update("delete from bank_applicant_ref where hire_id=?", id); // one live reference per attempt
        Instant expires = db.queryForObject("insert into bank_applicant_ref(ref_hash,hire_id,expires_at) values (?,?,now() + make_interval(secs => ?)) returning expires_at",
            java.sql.Timestamp.class, BankController.hash(ref), id, REF_LIFETIME.toSeconds()).toInstant();
        bank.audit(id, "INVITE_OPENED", "applicant", "authr");
        return Map.of("applicantRef", ref, "expiresAt", expires.toString(), "stage", stage(id));
    }

    @GetMapping("/applicants/{ref}")
    Map<String, Object> applicant(@PathVariable String ref) {
        UUID id = hireFor(ref);
        var hire = db.queryForMap("select expected_given from bank_hire where id=?", id);
        return Map.of("stage", stage(id), "givenName", Objects.toString(hire.get("expected_given"), ""));
    }

    @PostMapping("/applicants/{ref}/presentations") @Transactional
    Map<String, Object> startPassportPresentation(@PathVariable String ref) {
        UUID id = hireFor(ref);
        db.queryForMap("select id from bank_hire where id=? for update", id);
        if (!bank.awaitingIdentity(id)) throw new JourneyRefusal(HttpStatus.CONFLICT, "wrong_stage");
        return started(bank.newPresentation(id, "authr"));
    }

    @PostMapping("/applicants/{ref}/credential-offers") @Transactional
    Map<String, Object> offer(@PathVariable String ref) throws Exception {
        UUID id = hireFor(ref);
        var hire = db.queryForMap("select * from bank_hire where id=? for update", id);
        // As the portal's offer, and also refused once a newer attempt exists (issuance would refuse it anyway).
        if (!Set.of("APPROVED", "ACTIVE").contains(hire.get("status")) || superseded(id)) throw new JourneyRefusal(HttpStatus.CONFLICT, "wrong_stage");
        String offer = bank.staffOffer(hire);
        bank.audit(id, "OFFER_CREATED", "applicant", "authr");
        return Map.of("offerUri", BankController.offerUri(offer), "expiresAt", Instant.now().plusSeconds(600).toString());
    }

    // ── Staff sign-in ────────────────────────────────────────────────────────────────────────────────────────────────────────

    @PostMapping("/staff-sign-in/presentations")
    Map<String, Object> startStaffPresentation(@AuthenticationPrincipal Jwt caller) {
        // Anyone can start a sign-in, so this is where rows could be created without limit.
        String client = caller == null ? "unknown" : Objects.toString(caller.getClaims().get("client_id"), caller.getSubject());
        var window = staffStarts.computeIfAbsent(client, k -> new ArrayDeque<>());
        synchronized (window) {
            Instant cutoff = Instant.now().minusSeconds(60);
            while (!window.isEmpty() && window.peekFirst().isBefore(cutoff)) window.pollFirst();
            if (window.size() >= staffStartsPerMinute) throw new JourneyRefusal(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");
            window.addLast(Instant.now());
        }
        return started(bank.newPresentation(null, "authr"));
    }

    // ── Presentation results ─────────────────────────────────────────────────────────────────────────────────────────────────

    @GetMapping("/presentations/{id}")
    Map<String, Object> presentation(@PathVariable String id, @RequestHeader(value = "X-Completion-Secret", required = false) String secret) {
        var tx = ownPresentation(id, secret, false);
        boolean expired = !Boolean.TRUE.equals(tx.get("live"));
        // The same answer as the portal's /vp/status: an expired request reports expired even if the wallet completed it.
        return Map.of("status", expired ? "expired" : Boolean.TRUE.equals(tx.get("complete")) ? "complete" : "pending");
    }

    @PostMapping("/presentations/{id}/consume") @Transactional
    Map<String, Object> consume(@PathVariable String id, @RequestHeader(value = "X-Completion-Secret", required = false) String secret) {
        var tx = ownPresentation(id, secret, true);
        if (!Boolean.TRUE.equals(tx.get("live"))) throw new JourneyRefusal(HttpStatus.CONFLICT, "expired");
        if (!Boolean.TRUE.equals(tx.get("complete"))) throw new JourneyRefusal(HttpStatus.CONFLICT, "not_complete");
        if (tx.get("consumed_at") != null) throw new JourneyRefusal(HttpStatus.CONFLICT, "already_consumed");
        db.update("update bank_presentation set consumed_at=now() where id=?", id);
        if (tx.get("staff_id") instanceof UUID staff) {
            // Checked again now, not only when the wallet presented: approval may have been revoked (or a newer attempt started) since.
            try { bank.active(staff); } catch (ResponseStatusException inactive) { throw new JourneyRefusal(HttpStatus.CONFLICT, "staff_inactive"); }
            bank.audit(staff, "STAFF_SIGN_IN", "staff", "authr");
            if (directory == null) return Map.of("staffSubject", staff.toString());
            directory.changed(staff);
            // The identity signed in is the PERSON (one AuthStack user across reactivations); StaffSignIn maps it back to the current attempt.
            return Map.of("staffSubject", directory.personOf(staff).toString());
        }
        UUID hire = (UUID) tx.get("hire_id");
        return Map.of("stage", stage(hire));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

    private Map<String, Object> started(BankController.NewPresentation p) {
        return Map.of("presentationId", p.id(), "completionSecret", p.secret(), "walletUri", p.walletUri(), "requestUri", p.requestUri(), "expiresAt", p.expiresAt().toString());
    }

    /** A presentation this API started (with `live`: unexpired by the database's clock, which also set the expiry), with its completion secret. Anything else (unknown, another channel's, wrong secret) is 404. */
    private Map<String, Object> ownPresentation(String id, String secret, boolean lock) {
        var rows = db.queryForList("select *, expires_at > now() as live from bank_presentation where id=? and channel='authr'" + (lock ? " for update" : ""), id);
        if (rows.size() != 1 || secret == null || !BankController.hash(secret).equals(rows.getFirst().get("browser_secret_hash"))) throw new JourneyRefusal(HttpStatus.NOT_FOUND, "unknown_presentation");
        return rows.getFirst();
    }

    private UUID hireFor(String ref) {
        var rows = db.queryForList("select hire_id from bank_applicant_ref where ref_hash=? and expires_at>now()", BankController.hash(ref));
        if (rows.size() != 1) throw new JourneyRefusal(HttpStatus.NOT_FOUND, "unknown_applicant");
        return (UUID) rows.getFirst().get("hire_id");
    }

    private boolean superseded(UUID id) {
        return db.queryForObject("select count(*) from bank_hire where previous_hire_id=?", Integer.class, id) > 0;
    }

    /** Where the applicant is, for the journey to route on. Derived here, never sent by the caller. */
    String stage(UUID id) {
        if (superseded(id)) return "closed";
        String status = db.queryForObject("select status from bank_hire where id=?", String.class, id);
        return switch (status) {
            case "INVITED" -> "present";
            case "REVIEW" -> "in_review";
            case "APPROVED" -> "collect";
            case "ACTIVE" -> "active";
            default -> "closed";
        };
    }
}
