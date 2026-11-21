package com.darkedges.oid4vci.issuer.jdbc;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The table {@code oid4vci_issuer_entry}, which every store here shares, one {@code kind} each.
 *
 * <ul>
 *   <li>Keys are stored as their SHA-256: a pre-authorized code or a nonce is a bearer secret, so reading the table must not yield
 *       one.</li>
 *   <li>Payloads (a code's claims are someone's identity details) are encrypted with AES-256-GCM, bound to their kind and key, so a
 *       payload moved to another row doesn't decrypt.</li>
 *   <li>{@link #take} reads and removes in one statement ({@code DELETE … RETURNING}), so a single-use entry is used once even when
 *       several instances race for it.</li>
 *   <li>Expired rows are swept now and then as entries are added.</li>
 * </ul>
 * Expiry is compared with the application's clock, the one its callers use, not the database's.
 */
public final class IssuerEntryTable {

    /** A stored entry, decrypted. */
    public record Entry(byte[] payload, Instant expiresAt) {}

    private static final byte VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SWEEP_EVERY = 200;

    private final JdbcClient jdbc;
    private final SecretKeySpec key;
    private final AtomicLong writes = new AtomicLong();

    public IssuerEntryTable(JdbcClient jdbc, byte[] encryptionKey) {
        if (encryptionKey == null || encryptionKey.length != 32) {
            throw new IllegalArgumentException("oid4vci.issuer.store.encryption-key must be base64 of 32 random bytes");
        }
        this.jdbc = jdbc;
        this.key = new SecretKeySpec(encryptionKey.clone(), "AES");
    }

    public static IssuerEntryTable create(JdbcClient jdbc, String base64EncryptionKey) {
        if (base64EncryptionKey == null || base64EncryptionKey.isBlank()) {
            throw new IllegalArgumentException("oid4vci.issuer.store.encryption-key is required for the jdbc store "
                    + "(base64 of 32 random bytes): the stores hold identity claims");
        }
        return new IssuerEntryTable(jdbc, Base64.getDecoder().decode(base64EncryptionKey.trim()));
    }

    /** Adds or replaces an entry. */
    public void put(String kind, String key, byte[] payload, Instant expiresAt) {
        String hashed = hash(key);
        jdbc.sql("""
                INSERT INTO oid4vci_issuer_entry (kind, key, payload, expires_at) VALUES (?, ?, ?, ?)
                ON CONFLICT (kind, key) DO UPDATE SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at
                """).params(kind, hashed, payload == null ? null : encrypt(payload, kind, hashed), Timestamp.from(expiresAt)).update();
        maybeSweep();
    }

    /**
     * Adds an entry unless an unexpired one has this key: for replay records.
     *
     * @return whether it was added (that is, the key had not been used)
     */
    public boolean insertIfUnused(String kind, String key, Instant now, Instant expiresAt) {
        String hashed = hash(key);
        try {
            int changed = jdbc.sql("""
                    INSERT INTO oid4vci_issuer_entry (kind, key, payload, expires_at) VALUES (?, ?, NULL, ?)
                    ON CONFLICT (kind, key) DO UPDATE SET expires_at = EXCLUDED.expires_at
                        WHERE oid4vci_issuer_entry.expires_at <= ?
                    """).params(kind, hashed, Timestamp.from(expiresAt), Timestamp.from(now)).update();
            maybeSweep();
            return changed == 1;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    /** Reads and removes the entry, if there is one. Expiry is the caller's to check. */
    public Optional<Entry> take(String kind, String key) {
        String hashed = hash(key);
        return jdbc.sql("DELETE FROM oid4vci_issuer_entry WHERE kind = ? AND key = ? RETURNING payload, expires_at")
                .params(kind, hashed)
                .query((rs, row) -> new Entry(decryptOrNull(rs.getBytes("payload"), kind, hashed), rs.getTimestamp("expires_at").toInstant()))
                .optional();
    }

    /** Reads the entry without removing it. */
    public Optional<Entry> get(String kind, String key) {
        String hashed = hash(key);
        return jdbc.sql("SELECT payload, expires_at FROM oid4vci_issuer_entry WHERE kind = ? AND key = ?")
                .params(kind, hashed)
                .query((rs, row) -> new Entry(decryptOrNull(rs.getBytes("payload"), kind, hashed), rs.getTimestamp("expires_at").toInstant()))
                .optional();
    }

    public void remove(String kind, String key) {
        jdbc.sql("DELETE FROM oid4vci_issuer_entry WHERE kind = ? AND key = ?").params(kind, hash(key)).update();
    }

    /** Deletes every entry that expired over five minutes ago (a margin for clocks that disagree). Returns how many. */
    public int sweep() {
        return jdbc.sql("DELETE FROM oid4vci_issuer_entry WHERE expires_at < now() - interval '5 minutes'").update();
    }

    private void maybeSweep() {
        if (writes.incrementAndGet() % SWEEP_EVERY == 0) sweep();
    }

    static String hash(String key) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] encrypt(byte[] plaintext, String kind, String hashedKey) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(kind, hashedKey));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(1 + NONCE_BYTES + ciphertext.length).put(VERSION).put(nonce).put(ciphertext).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not encrypt an issuer entry", e);
        }
    }

    private byte[] decryptOrNull(byte[] stored, String kind, String hashedKey) {
        if (stored == null) return null;
        if (stored.length < 1 + NONCE_BYTES + 16 || stored[0] != VERSION) throw new IllegalStateException("unreadable issuer entry");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Arrays.copyOfRange(stored, 1, 1 + NONCE_BYTES)));
            cipher.updateAAD(aad(kind, hashedKey));
            return cipher.doFinal(stored, 1 + NONCE_BYTES, stored.length - 1 - NONCE_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not decrypt an issuer entry: wrong oid4vci.issuer.store.encryption-key, or the row was moved", e);
        }
    }

    private static byte[] aad(String kind, String hashedKey) {
        return ("oid4vci-issuer-entry|" + kind + "|" + hashedKey).getBytes(StandardCharsets.UTF_8);
    }
}
