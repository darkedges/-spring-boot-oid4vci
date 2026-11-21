package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.issuer.jdbc.IssuerEntryTable;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * Proofing sessions in the issuer's PostgreSQL table ({@code oid4vci-issuer-jdbc}, kind {@value #KIND}), so a Wallet can collect
 * its offer from any instance, and after a restart. Encrypted like every entry there: a session holds a pre-authorized code and the
 * Wallet's retrieval secret.
 */
public final class JdbcProofingSessionStore implements ProofingSessionStore {

    static final String KIND = "proofing_session";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final IssuerEntryTable table;

    public JdbcProofingSessionStore(IssuerEntryTable table) {
        this.table = table;
    }

    @Override
    public void save(ProofingSession session) {
        ObjectNode node = MAPPER.createObjectNode()
                .put("id", session.id())
                .put("retrievalSecret", session.retrievalSecret())
                .put("status", session.status().name())
                .put("expiresAt", session.expiresAt().toString())
                .put("tenantId", session.tenantId());
        session.preAuthorizedCode().ifPresent(c -> node.put("preAuthorizedCode", c));
        session.credentialConfigurationId().ifPresent(c -> node.put("credentialConfigurationId", c));
        session.failureReason().ifPresent(r -> node.put("failureReason", r));
        try {
            table.put(KIND, session.id(), MAPPER.writeValueAsBytes(node), session.expiresAt());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Optional<ProofingSession> find(String id, Instant now) {
        if (id == null || id.isBlank()) return Optional.empty();
        return table.get(KIND, id).map(entry -> read(entry.payload())).filter(session -> !session.isExpired(now));
    }

    @Override
    public void evictExpired(Instant now) {
        // The table sweeps expired entries itself as new ones are added.
    }

    private static ProofingSession read(byte[] payload) {
        try {
            JsonNode n = MAPPER.readTree(payload);
            return new ProofingSession(n.path("id").asText(), n.path("retrievalSecret").asText(),
                    ProofingSession.Status.valueOf(n.path("status").asText()), text(n, "preAuthorizedCode"),
                    text(n, "credentialConfigurationId"), text(n, "failureReason"), Instant.parse(n.path("expiresAt").asText()),
                    n.path("tenantId").asText(null));
        } catch (IOException e) {
            throw new IllegalStateException("unreadable proofing session", e);
        }
    }

    private static Optional<String> text(JsonNode node, String field) {
        return node.hasNonNull(field) ? Optional.of(node.get(field).asText()) : Optional.empty();
    }
}
