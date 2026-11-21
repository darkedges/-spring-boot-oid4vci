package com.darkedges.oid4vci.issuer.jdbc;

import com.darkedges.oid4vci.core.authorize.AuthorizationRequest;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferReader;
import com.darkedges.oid4vci.core.offer.CredentialOfferWriter;
import com.darkedges.oid4vci.core.token.AuthorizationDetail;
import com.darkedges.oid4vci.issuer.AuthorizationCodeEntry;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The JSON form of each stored type. Explicit, so a stored entry reads back the same after a library upgrade. */
final class IssuerEntryCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private IssuerEntryCodec() {}

    // ---- PreAuthorizedCodeSession

    static ObjectNode session(PreAuthorizedCodeSession session) {
        ObjectNode node = MAPPER.createObjectNode();
        ArrayNode ids = node.putArray("credentialConfigurationIds");
        session.credentialConfigurationIds().forEach(ids::add);
        session.expectedTxCode().ifPresent(tx -> node.put("txCode", tx));
        ObjectNode claims = node.putObject("claims");
        session.claims().forEach(claims::put);
        node.put("expiresAt", session.expiresAt().toString());
        return node;
    }

    static PreAuthorizedCodeSession session(JsonNode node) {
        List<String> ids = new ArrayList<>();
        node.path("credentialConfigurationIds").forEach(id -> ids.add(id.asText()));
        Map<String, String> claims = new LinkedHashMap<>();
        node.path("claims").fields().forEachRemaining(e -> claims.put(e.getKey(), e.getValue().asText()));
        return new PreAuthorizedCodeSession(ids, optionalText(node, "txCode"), claims, Instant.parse(node.path("expiresAt").asText()));
    }

    // ---- AuthorizationCodeEntry

    static ObjectNode authorizationCode(AuthorizationCodeEntry entry) {
        ObjectNode node = MAPPER.createObjectNode();
        node.set("session", session(entry.session()));
        node.put("redirectUri", entry.redirectUri().toString());
        entry.codeChallenge().ifPresent(c -> node.put("codeChallenge", c));
        entry.codeChallengeMethod().ifPresent(m -> node.put("codeChallengeMethod", m));
        return node;
    }

    static AuthorizationCodeEntry authorizationCode(JsonNode node) {
        return new AuthorizationCodeEntry(session(node.path("session")), URI.create(node.path("redirectUri").asText()),
                optionalText(node, "codeChallenge"), optionalText(node, "codeChallengeMethod"));
    }

    // ---- PushedAuthorizationRequestEntry

    static ObjectNode pushedRequest(PushedAuthorizationRequestEntry entry) {
        AuthorizationRequest request = entry.request();
        ObjectNode node = MAPPER.createObjectNode();
        node.put("expiresAt", entry.expiresAt().toString());
        node.put("responseType", request.responseType());
        if (request.clientId() != null) node.put("clientId", request.clientId());
        node.put("redirectUri", request.redirectUri().toString());
        request.state().ifPresent(s -> node.put("state", s));
        request.codeChallenge().ifPresent(c -> node.put("codeChallenge", c));
        request.codeChallengeMethod().ifPresent(m -> node.put("codeChallengeMethod", m));
        ArrayNode details = node.putArray("authorizationDetails");
        for (AuthorizationDetail detail : request.authorizationDetails()) {
            ObjectNode d = details.addObject().put("credentialConfigurationId", detail.credentialConfigurationId());
            detail.credentialIdentifiers().ifPresent(ids -> ids.forEach(d.putArray("credentialIdentifiers")::add));
        }
        ArrayNode scopes = node.putArray("scopes");
        request.scopes().forEach(scopes::add);
        return node;
    }

    static PushedAuthorizationRequestEntry pushedRequest(JsonNode node) {
        List<AuthorizationDetail> details = new ArrayList<>();
        for (JsonNode d : node.path("authorizationDetails")) {
            Optional<List<String>> ids = Optional.empty();
            if (d.has("credentialIdentifiers")) {
                List<String> list = new ArrayList<>();
                d.get("credentialIdentifiers").forEach(i -> list.add(i.asText()));
                ids = Optional.of(list);
            }
            details.add(new AuthorizationDetail(d.path("credentialConfigurationId").asText(), ids));
        }
        List<String> scopes = new ArrayList<>();
        node.path("scopes").forEach(s -> scopes.add(s.asText()));
        AuthorizationRequest request = new AuthorizationRequest(node.path("responseType").asText(),
                node.hasNonNull("clientId") ? node.get("clientId").asText() : null, URI.create(node.path("redirectUri").asText()),
                optionalText(node, "state"), optionalText(node, "codeChallenge"), optionalText(node, "codeChallengeMethod"),
                details, scopes);
        return new PushedAuthorizationRequestEntry(request, Instant.parse(node.path("expiresAt").asText()));
    }

    // ---- claims and offers

    static ObjectNode claims(Map<String, String> claims) {
        ObjectNode node = MAPPER.createObjectNode();
        claims.forEach(node::put);
        return node;
    }

    static Map<String, String> claims(JsonNode node) {
        Map<String, String> claims = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> claims.put(e.getKey(), e.getValue().asText()));
        return Map.copyOf(claims);
    }

    static JsonNode offer(CredentialOffer offer) {
        return CredentialOfferWriter.write(offer);
    }

    static CredentialOffer offer(JsonNode node) {
        return CredentialOfferReader.read(node);
    }

    // ----

    static byte[] bytes(JsonNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static JsonNode read(byte[] bytes) {
        try {
            return MAPPER.readTree(bytes);
        } catch (IOException e) {
            throw new IllegalStateException("unreadable issuer entry", e);
        }
    }

    private static Optional<String> optionalText(JsonNode node, String field) {
        return node.hasNonNull(field) ? Optional.of(node.get(field).asText()) : Optional.empty();
    }
}
