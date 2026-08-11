package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.issuer.InMemoryPreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The proofing endpoints.
 *
 * <p>Weighted towards what an attacker can reach rather than the happy path, because the happy path
 * fails visibly in end-to-end testing and these do not: an unauthenticated callback mints a
 * credential that looks exactly like a real one.
 */
class ProofingControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SECRET = "a-shared-secret-from-the-environment";

    private Clock clock;
    private ProofingSessionStore sessionStore;
    private PreAuthorizedCodeStore codeStore;
    private ProofingProperties properties;
    private ProofingController controller;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(Instant.parse("2026-08-11T00:00:00Z"), ZoneOffset.UTC);
        sessionStore = new InMemoryProofingSessionStore();
        codeStore = new InMemoryPreAuthorizedCodeStore();
        properties = new ProofingProperties();
        properties.setCallbackSecret(SECRET);
        controller = newController();
    }

    private ProofingController newController() {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.of("/nonce"),
                Map.of("PassportCredential", new SdJwtVcCredentialConfiguration(
                        "/vct/PassportCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));
        return new ProofingController(
                sessionStore, codeStore, template, new PassportClaimsMapper(clock), properties, clock);
    }

    private static MockHttpServletRequest servletRequest() {
        return servletRequestFrom("https", "issuer.example.org", 443);
    }

    private static MockHttpServletRequest servletRequestFrom(String scheme, String host, int port) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(scheme);
        request.setServerName(host);
        request.setServerPort(port);
        return request;
    }

    private static ProofingResultRequest passingResultFor(String sessionId) {
        return new ProofingResultRequest(
                sessionId, "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, true, true, true, true);
    }

    private String startSession() throws Exception {
        return MAPPER.readTree(controller.createSession()).get("session_id").asText();
    }

    private String secretFor(String createSessionBody) throws Exception {
        return MAPPER.readTree(createSessionBody).get("retrieval_secret").asText();
    }

    @Test
    void issuesASessionIdAndARetrievalSecretThatDiffer() throws Exception {
        JsonNode body = MAPPER.readTree(controller.createSession());

        assertThat(body.get("session_id").asText()).isNotBlank();
        assertThat(body.get("retrieval_secret").asText()).isNotBlank();
        // If the secret were derivable from the id, intercepting the deep link would be enough to
        // collect the credential -- which is the entire threat the secret exists to answer.
        assertThat(body.get("retrieval_secret").asText()).isNotEqualTo(body.get("session_id").asText());
    }

    @Test
    void rejectsAResultCallbackWithNoSecret() throws Exception {
        String sessionId = startSession();

        ResponseEntity<String> response = controller.receiveResult(null, passingResultFor(sessionId), servletRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsAResultCallbackWithTheWrongSecret() throws Exception {
        String sessionId = startSession();

        ResponseEntity<String> response =
                controller.receiveResult("not-the-secret", passingResultFor(sessionId), servletRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void refusesEveryCallbackWhenNoSecretIsConfigured() throws Exception {
        // A deployment that forgot to set the secret must fail closed. Failing open here would mean
        // anyone able to reach the host could mint a credential asserting any identity, and nothing
        // about the running system would look wrong.
        properties.setCallbackSecret(null);
        controller = newController();
        String sessionId = startSession();

        assertThat(controller.receiveResult(null, passingResultFor(sessionId), servletRequest()).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(controller.receiveResult("", passingResultFor(sessionId), servletRequest()).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void mintsAnOfferCarryingTheProofedIdentity() throws Exception {
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();

        controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());
        JsonNode polled = MAPPER.readTree(
                controller.pollSession(sessionId, secretFor(created), servletRequest()).getBody());

        assertThat(polled.get("status").asText()).isEqualTo("ready");
        JsonNode offer = polled.get("credential_offer");
        assertThat(offer.get("credential_configuration_ids").get(0).asText()).isEqualTo("PassportCredential");

        // The claims must be reachable through the code the offer carries -- an offer whose code does
        // not resolve to the proofed identity is a credential for nobody.
        String code = offer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .get("pre-authorized_code").asText();
        PreAuthorizedCodeSession session = codeStore.consume(code).orElseThrow();
        assertThat(session.claims())
                .containsEntry("family_name", "FITZGERALD")
                .containsEntry("birth_date", "1987-03-14");
    }

    @Test
    void addressesTheOfferAsTheWalletReachedThisIssuer() throws Exception {
        // The two callers arrive at different addresses, which is the normal deployed case: the
        // proofing service reaches this issuer over the internal network, the Wallet over the public
        // hostname. credential_issuer must be the Wallet's, since the Wallet is what has to resolve
        // it -- taking it from the callback would hand a phone an in-cluster name it cannot reach.
        //
        // Every other test here used one address for both, so this passed locally while being wrong.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();

        controller.receiveResult(
                SECRET, passingResultFor(sessionId), servletRequestFrom("http", "issuer.internal", 8092));
        JsonNode offer = MAPPER.readTree(controller
                        .pollSession(sessionId, secretFor(created), servletRequestFrom("https", "issuer.zkp.au", 443))
                        .getBody())
                .get("credential_offer");

        assertThat(offer.get("credential_issuer").asText()).isEqualTo("https://issuer.zkp.au");
    }

    @Test
    void deliversTheOfferAsJsonRatherThanAnEncodedString() throws Exception {
        // Built as a node, not spliced in as text: handing the Wallet a JSON string containing JSON
        // is something its parser accepts and then fails to navigate.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());

        JsonNode offer = MAPPER.readTree(controller.pollSession(sessionId, secretFor(created), servletRequest()).getBody())
                .get("credential_offer");

        assertThat(offer.isObject()).isTrue();
    }

    @Test
    void doesNotHandTheOfferToACallerWithoutTheRetrievalSecret() throws Exception {
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());

        // An app that hijacked the deep-link scheme holds the id and nothing else.
        ResponseEntity<String> response = controller.pollSession(sessionId, "guessed", servletRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).doesNotContain("credential_offer");
    }

    @Test
    void doesNotConfirmThatAnIdWasRealWhenTheSecretIsWrong() throws Exception {
        // Same 404 for a wrong secret as for an unknown id, so polling cannot be used to discover
        // which session ids exist.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();

        ResponseEntity<String> wrongSecret = controller.pollSession(sessionId, "guessed", servletRequest());
        ResponseEntity<String> unknownId = controller.pollSession("no-such-session", "guessed", servletRequest());

        assertThat(wrongSecret.getStatusCode()).isEqualTo(unknownId.getStatusCode());
        assertThat(wrongSecret.getBody()).isEqualTo(unknownId.getBody());
    }

    @Test
    void doesNotMintAnOfferForAResultThatDidNotPass() throws Exception {
        // The proofing service is only supposed to call on success, but the issuer decides what it
        // issues. Trusting the caller's judgement would put this issuer's policy in another codebase.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        ProofingResultRequest failed = new ProofingResultRequest(
                sessionId, "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, false, true, true, true, true, true, true);

        controller.receiveResult(SECRET, failed, servletRequest());
        JsonNode polled = MAPPER.readTree(controller.pollSession(sessionId, secretFor(created), servletRequest()).getBody());

        assertThat(polled.get("status").asText()).isEqualTo("failed");
        assertThat(polled.has("credential_offer")).isFalse();
    }

    @Test
    void refusesAResultWhoseFaceCameFromTheDeviceRatherThanTheChip() throws Exception {
        // Without portraitFromChip the match score describes a picture the device chose, so a genuine
        // passport could be paired with somebody else's selfie and still score perfectly.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        ProofingResultRequest deviceSuppliedFace = new ProofingResultRequest(
                sessionId, "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, true, true, false, true);

        controller.receiveResult(SECRET, deviceSuppliedFace, servletRequest());

        assertThat(MAPPER.readTree(controller.pollSession(sessionId, secretFor(created), servletRequest()).getBody())
                .get("status").asText()).isEqualTo("failed");
    }

    @Test
    void treatsAnUndeterminedChainCheckAsNotProved() throws Exception {
        // null is "never ran". It must not read as a pass -- Boolean.TRUE.equals is what makes that so,
        // and a primitive boolean here would have quietly turned every unknown into false anyway.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        ProofingResultRequest unknownChain = new ProofingResultRequest(
                sessionId, "ALEXANDRA JANE", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, null, true, true, true);

        controller.receiveResult(SECRET, unknownChain, servletRequest());

        assertThat(MAPPER.readTree(controller.pollSession(sessionId, secretFor(created), servletRequest()).getBody())
                .get("status").asText()).isEqualTo("failed");
    }

    @Test
    void doesNotMintASecondOfferForAReplayedCallback() throws Exception {
        // A replayed callback must not overwrite an offer still waiting to be collected, or one
        // proofing run yields two credentials.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());

        ResponseEntity<String> replay = controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());

        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void rejectsAResultForASessionThatWasNeverStarted() throws Exception {
        // Without this, the callback alone would be enough to mint a credential -- no Wallet, no user,
        // no proofing run.
        ResponseEntity<String> response =
                controller.receiveResult(SECRET, passingResultFor("invented-session"), servletRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void rejectsAResultMissingIdentityFieldsTheCredentialWouldAssert() throws Exception {
        String sessionId = startSession();
        ProofingResultRequest noDocumentNumber = new ProofingResultRequest(
                sessionId, "ALEXANDRA JANE", "FITZGERALD", "870314", "  ", "GBR", "GBR", "310612",
                true, true, true, true, true, true, true, true);

        ResponseEntity<String> response = controller.receiveResult(SECRET, noDocumentNumber, servletRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void acceptsAMononymousHolder() throws Exception {
        // ICAO 9303 allows a document with a primary identifier and no given names. Rejecting those
        // would be a bug affecting exactly the people least able to work around it.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        ProofingResultRequest mononymous = new ProofingResultRequest(
                sessionId, "", "FITZGERALD", "870314", "PA1234567", "GBR", "GBR", "310612",
                true, true, true, true, true, true, true, true);

        controller.receiveResult(SECRET, mononymous, servletRequest());

        assertThat(MAPPER.readTree(controller.pollSession(sessionId, secretFor(created), servletRequest()).getBody())
                .get("status").asText()).isEqualTo("ready");
    }

    @Test
    void forgetsASessionOnceItHasExpired() throws Exception {
        // The session holds a Credential Offer whose code still points at real passport claims, so an
        // abandoned one must not linger for the life of the process.
        String created = controller.createSession();
        String sessionId = MAPPER.readTree(created).get("session_id").asText();
        controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());

        Instant afterExpiry = clock.instant().plus(properties.getSessionTtl()).plus(Duration.ofSeconds(1));
        assertThat(sessionStore.find(sessionId, afterExpiry)).isEmpty();

        sessionStore.evictExpired(afterExpiry);
        assertThat(sessionStore.find(sessionId, afterExpiry)).isEmpty();
    }

    @Test
    void rejectsAResultForAnExpiredSession() throws Exception {
        String sessionId = startSession();
        clock = Clock.fixed(
                clock.instant().plus(properties.getSessionTtl()).plus(Duration.ofSeconds(1)), ZoneOffset.UTC);
        controller = newController();

        ResponseEntity<String> response =
                controller.receiveResult(SECRET, passingResultFor(sessionId), servletRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
