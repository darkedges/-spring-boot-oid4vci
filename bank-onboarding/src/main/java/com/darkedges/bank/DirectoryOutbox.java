package com.darkedges.bank;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.util.*;

/**
 * People whose AuthStack user needs bringing up to date. A person is the chain of attempts that reactivation creates (each attempt a
 * bank_hire row, linked by previous_hire_id); the first attempt's id is the person's id, and the person's AuthStack user carries it.
 *
 * Every change to a person (a hire created, a Passport presented, a decision, a reactivation, a credential issued, a staff sign-in)
 * marks them changed in the same transaction as the change itself, so nothing is lost if the bank stops before AuthStack hears of it.
 * AuthStackDirectory then sends the person's whole current state, built from the database at that moment, so a retry or a repeat is
 * always correct.
 */
@Component
public class DirectoryOutbox {
    private final JdbcTemplate db;

    public DirectoryOutbox(JdbcTemplate db) { this.db = db; }

    /** The person (the chain's first attempt) this attempt belongs to. */
    static final String PERSON_OF = """
        with recursive up as (select id, previous_hire_id from bank_hire where id=?
          union all select h.id, h.previous_hire_id from bank_hire h join up on h.id=up.previous_hire_id)
        select id from up where previous_hire_id is null""";

    /** The person's current attempt: the last of the chain, starting from any attempt of it. */
    static final String CURRENT_ATTEMPT = """
        with recursive down as (select id from bank_hire where id=?
          union all select h.id from bank_hire h join down on h.previous_hire_id=down.id)
        select id from down where not exists (select 1 from bank_hire newer where newer.previous_hire_id=down.id)""";

    public UUID personOf(UUID attemptId) {
        var rows = db.queryForList(PERSON_OF, UUID.class, attemptId);
        return rows.isEmpty() ? attemptId : rows.getFirst();
    }

    public Optional<UUID> currentAttempt(UUID anyAttempt) {
        var rows = db.queryForList(CURRENT_ATTEMPT, UUID.class, anyAttempt);
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.getFirst());
    }

    /** Mark this attempt's person changed. Call inside the transaction that made the change. */
    public void changed(UUID attemptId) {
        db.update("""
            insert into bank_directory_outbox(person_id, changed_at, next_attempt_at, attempts) values (?, now(), now(), 0)
            on conflict (person_id) do update set changed_at=now(), next_attempt_at=now(), attempts=0""", personOf(attemptId));
    }

    /** For HR's card: synced, pending or failed (with the last error), or null when the person has never been queued. */
    public Map<String, Object> state(UUID attemptId) {
        var rows = db.queryForList("select changed_at, synced_at, last_error from bank_directory_outbox where person_id=?", personOf(attemptId));
        if (rows.isEmpty()) return null;
        var row = rows.getFirst();
        boolean synced = row.get("synced_at") != null && !((java.sql.Timestamp) row.get("synced_at")).before((java.sql.Timestamp) row.get("changed_at"));
        String state = synced ? "synced" : row.get("last_error") != null ? "failed" : "pending";
        var out = new LinkedHashMap<String, Object>();
        out.put("state", state);
        out.put("error", row.get("last_error"));
        return out;
    }
}
