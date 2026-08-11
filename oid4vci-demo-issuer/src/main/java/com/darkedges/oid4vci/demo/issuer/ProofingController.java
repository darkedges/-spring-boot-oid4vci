package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferWriter;
import com.darkedges.oid4vci.core.offer.Grants;
import com.darkedges.oid4vci.core.offer.PreAuthorizedCodeGrant;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.web.RequestBaseUrl;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Issues a Credential Offer against a completed identity-proofing run, replacing
 * {@code DemoOfferController}'s hardcoded {@code Jane Doe} with claims taken from a real passport.
 *
 * <p>Three endpoints, and the split between them is what makes the flow safe:
 *
 * <ul>
 *   <li>{@code POST /proofing/session} — a Wallet asks to be proofed. Public: it asserts nothing and
 *       receives nothing but two random strings.
 *   <li>{@code POST /proofing/result} — the proofing service reports a verified identity.
 *       <strong>Authenticated.</strong> This is the endpoint that decides what a credential says, so
 *       an unauthenticated one is direct claim injection: anyone able to reach the host could mint a
 *       credential asserting any identity they chose. Note it is not under {@code /demo/**}, which is
 *       already {@code permitAll}.
 *   <li>{@code GET /proofing/session/{id}} — the Wallet collects its offer, presenting the retrieval
 *       secret it was given at the start.
 * </ul>
 *
 * <p>Returns pre-serialized {@code String} bodies — see {@code IssuerMetadataController}'s Javadoc
 * (oid4vci-issuer-web) for why {@code ObjectNode} cannot be returned directly under Spring Boot 4.1.
 */
@RestController
public class ProofingController {

    private static final Logger log = LoggerFactory.getLogger(ProofingController.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ProofingSessionStore sessionStore;
    private final PreAuthorizedCodeStore codeStore;
    private final CredentialIssuerMetadataTemplate template;
    private final PassportClaimsMapper claimsMapper;
    private final ProofingProperties properties;
    private final Clock clock;

    public ProofingController(
            ProofingSessionStore sessionStore,
            PreAuthorizedCodeStore codeStore,
            CredentialIssuerMetadataTemplate template,
            PassportClaimsMapper claimsMapper,
            ProofingProperties properties,
            Clock clock) {
        this.sessionStore = sessionStore;
        this.codeStore = codeStore;
        this.template = template;
        this.claimsMapper = claimsMapper;
        this.properties = properties;
        this.clock = clock;
    }

    /** Starts a session. The Wallet keeps {@code retrieval_secret} and sends only {@code session_id}
     * onward to the proofing app. */
    @PostMapping(value = "/proofing/session", produces = MediaType.APPLICATION_JSON_VALUE)
    public String createSession() {
        Instant now = clock.instant();
        sessionStore.evictExpired(now);

        ProofingSession session = ProofingSession.pending(
                randomToken(), randomToken(), now.plus(properties.getSessionTtl()));
        sessionStore.save(session);

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("session_id", session.id());
        body.put("retrieval_secret", session.retrievalSecret());
        body.put("expires_in", properties.getSessionTtl().toSeconds());
        return body.toString();
    }

    /**
     * Receives a verified proofing result and mints the offer.
     *
     * <p>The claims go into the {@code PreAuthorizedCodeSession}; the proofing session keeps only the
     * offer. One copy of the passport data, behind one single-use code.
     */
    @PostMapping(value = "/proofing/result", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> receiveResult(
            @RequestHeader(value = "X-Proofing-Secret", required = false) String presentedSecret,
            @RequestBody ProofingResultRequest result,
            HttpServletRequest servletRequest) {

        if (!isAuthorised(presentedSecret)) {
            // No detail, deliberately: a caller who cannot authenticate learns nothing about whether
            // the secret is unset, wrong, or the session exists.
            log.warn("Rejected an unauthenticated proofing result callback");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\":\"unauthorized\"}");
        }

        if (result == null || !result.hasRequiredIdentityFields()) {
            return badRequest("the result is missing required identity fields");
        }

        Instant now = clock.instant();
        sessionStore.evictExpired(now);
        Optional<ProofingSession> found = sessionStore.find(result.sessionId(), now);
        if (found.isEmpty()) {
            // Covers both "never existed" and "expired", which the caller cannot act on differently.
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"error\":\"unknown_session\"}");
        }
        ProofingSession session = found.get();
        if (session.status() != ProofingSession.Status.PENDING) {
            // Not an error worth failing loudly over, but it must not overwrite an offer already
            // waiting to be collected: a replayed callback would otherwise mint a second credential.
            return ResponseEntity.status(HttpStatus.CONFLICT).body("{\"error\":\"session_already_completed\"}");
        }

        if (!result.isAcceptable()) {
            sessionStore.save(session.failed("verification did not pass"));
            log.info("Proofing session {} recorded as failed", session.id());
            return ResponseEntity.ok("{\"status\":\"failed\"}");
        }

        Map<String, String> claims;
        try {
            claims = claimsMapper.toClaims(result);
        } catch (IllegalArgumentException e) {
            // A date that will not parse is a bug in the caller, not a verification failure, and the
            // message never carries the value itself.
            log.warn("Proofing session {} supplied an unusable field: {}", session.id(), e.getMessage());
            return badRequest("a supplied field could not be interpreted");
        }

        String configurationId = properties.getCredentialConfigurationId();
        CredentialIssuerMetadata metadata = template.resolve(RequestBaseUrl.resolve(servletRequest));
        if (!metadata.credentialConfigurationsSupported().containsKey(configurationId)) {
            // Caught here rather than at the Credential Endpoint, where it would surface to the user
            // as a failure at the very end of a passport read they cannot repeat cheaply.
            log.error("Configured credential_configuration_id {} is not advertised by this issuer", configurationId);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"credential_configuration_not_supported\"}");
        }

        String code = randomToken();
        codeStore.save(code, new PreAuthorizedCodeSession(
                List.of(configurationId),
                Optional.empty(),
                claims,
                now.plus(properties.getPreAuthorizedCodeTtl())));

        CredentialOffer offer = new CredentialOffer(
                metadata.credentialIssuer(),
                List.of(configurationId),
                Optional.of(new Grants(Optional.empty(),
                        Optional.of(new PreAuthorizedCodeGrant(code, Optional.empty(), Optional.empty())))));

        sessionStore.save(session.ready(CredentialOfferWriter.write(offer).toString()));
        // The identity itself is never logged -- see the proofing service's own logging policy. That a
        // session completed is operationally useful; who it was about is not.
        log.info("Proofing session {} is ready to collect", session.id());
        return ResponseEntity.ok("{\"status\":\"ready\"}");
    }

    /**
     * Collects the offer.
     *
     * <p>The retrieval secret is required because the session id is not a secret: it travels to the
     * proofing app over an Android custom-scheme deep link, and any app on the device may claim that
     * scheme. Without this, intercepting the link would be enough to collect somebody else's identity
     * credential.
     */
    @GetMapping(value = "/proofing/session/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> pollSession(
            // Named explicitly rather than relying on the compiler's -parameters flag. Spring can infer
            // it, but only from a build configured to retain parameter names, and when that silently
            // stops being true the endpoint throws at runtime rather than failing to compile.
            @PathVariable("id") String id,
            @RequestParam(name = "secret", required = false) String secret) {

        Instant now = clock.instant();
        Optional<ProofingSession> found = sessionStore.find(id, now);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"error\":\"unknown_session\"}");
        }
        ProofingSession session = found.get();

        if (!constantTimeEquals(session.retrievalSecret(), secret)) {
            // 404 rather than 403: a wrong secret should not confirm that the id was real.
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"error\":\"unknown_session\"}");
        }

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("status", session.status().name().toLowerCase(Locale.ROOT));
        session.failureReason().ifPresent(reason -> body.put("reason", reason));
        if (session.status() == ProofingSession.Status.READY) {
            // Re-parsed rather than spliced in as text: the offer is stored serialized, and embedding
            // that string directly would deliver it to the Wallet double-encoded as a JSON string.
            try {
                body.set("credential_offer", MAPPER.readTree(session.credentialOffer().orElseThrow()));
            } catch (JsonProcessingException e) {
                log.error("Stored credential offer for session {} is not valid JSON", session.id(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("{\"error\":\"stored_offer_unreadable\"}");
            }
        }
        return ResponseEntity.ok(body.toString());
    }

    private boolean isAuthorised(String presentedSecret) {
        String expected = properties.getCallbackSecret();
        if (expected == null || expected.isBlank()) {
            // Fails closed. An unset secret means the deployment was not configured, not that the
            // endpoint is open -- an open one hands out credentials for any identity asked for.
            log.error("demo.proofing.callback-secret is not set; the result endpoint is refusing all calls");
            return false;
        }
        return constantTimeEquals(expected, presentedSecret);
    }

    /** Compares without leaking length or position through timing. */
    private static boolean constantTimeEquals(String expected, String presented) {
        if (presented == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
    }

    private static ResponseEntity<String> badRequest(String message) {
        return ResponseEntity.badRequest().body("{\"error\":\"invalid_request\",\"error_description\":\"" + message + "\"}");
    }

    /** 32 bytes, matching {@code DemoOfferController#randomCode} -- see its Javadoc for why a shorter
     * value can fail the conformance suite's entropy check. The session id and retrieval secret get
     * the same treatment, since both must resist being guessed by anyone who can reach the host. */
    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
