package com.darkedges.oid4vci.demo.wallet;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataReader;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferReader;
import com.darkedges.oid4vci.wallet.HolderBoundCredential;
import com.darkedges.oid4vci.wallet.WalletIssuanceOrchestrator;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQueryReader;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ClientMetadataReader;
import com.darkedges.oid4vp.core.response.VpToken;
import com.darkedges.oid4vp.core.response.VpTokenWriter;
import com.darkedges.oid4vp.wallet.HolderKeyResolver;
import com.darkedges.oid4vp.wallet.MdocPresentationBuilderAdapter;
import com.darkedges.oid4vp.wallet.PresentationBuildParams;
import com.darkedges.oid4vp.wallet.PresentationBuilder;
import com.darkedges.oid4vp.wallet.ResponseEncryptor;
import com.darkedges.oid4vp.wallet.SdJwtVcPresentationBuilderAdapter;
import com.darkedges.oid4vp.wallet.WalletAuthorizationResponseBuilder;
import com.darkedges.oid4vp.wallet.WalletAuthorizationResponseResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Drives the full pre-authorized_code flow against a real Credential Issuer (e.g.
 * {@code oid4vci-demo-issuer}) over HTTP: fetches its metadata and a demo offer, runs
 * {@link WalletIssuanceOrchestrator}, and stores the resulting {@link HeldCredential}s. Also exposes a
 * {@code /present} endpoint — the {@code oid4vci}-side counterpart of {@code oid4vp-demo-wallet}'s own
 * {@code WalletController.present(...)} (the reference implementation this mirrors almost line-for-line):
 * fetches an Authorization Request from a Verifier, evaluates it against the credentials obtained above,
 * and POSTs the resulting {@code vp_token} back — closing the cross-repo interop gap documented in the
 * project README (an oid4vci-obtained credential can now be presented to a separately-running
 * {@code oid4vp-demo-verifier}).
 *
 * <p>Returns pre-serialized {@code String} bodies, not {@code ObjectNode}/{@code JsonNode} directly —
 * see {@code oid4vci-issuer-web}'s {@code IssuerMetadataController} Javadoc for why, under Spring Boot
 * 4.1's Jackson 2/3 coexistence.
 */
@RestController
public class WalletController {

    private static final Logger log = LoggerFactory.getLogger(WalletController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final RestClient restClient = RestClient.create();
    private final WalletIssuanceOrchestrator orchestrator;
    private final MutableCredentialStore credentialStore;

    public WalletController(WalletIssuanceOrchestrator orchestrator, MutableCredentialStore credentialStore) {
        this.orchestrator = orchestrator;
        this.credentialStore = credentialStore;
    }

    @PostMapping(value = "/wallet/obtain", produces = MediaType.APPLICATION_JSON_VALUE)
    public String obtain(@RequestParam String issuerUrl) throws Exception {
        String metadataBody = restClient.get()
                .uri(issuerUrl + "/.well-known/openid-credential-issuer")
                .retrieve().body(String.class);
        CredentialIssuerMetadata metadata = CredentialIssuerMetadataReader.read(MAPPER.readTree(metadataBody));

        String offerBody = restClient.get().uri(issuerUrl + "/demo/offer").retrieve().body(String.class);
        CredentialOffer offer = CredentialOfferReader.read(MAPPER.readTree(offerBody));

        URI tokenEndpoint = URI.create(issuerUrl + "/token");
        List<HolderBoundCredential> obtained = orchestrator.obtainCredentials(offer, metadata, tokenEndpoint, Optional::empty);
        credentialStore.addAll(obtained);

        ObjectNode result = JsonNodeFactory.instance.objectNode();
        ArrayNode formats = result.putArray("obtained_formats");
        obtained.forEach(c -> formats.add(c.credential().format().identifier()));
        return result.toString();
    }

    @GetMapping(value = "/wallet/credentials", produces = MediaType.APPLICATION_JSON_VALUE)
    public String credentials() {
        ArrayNode array = JsonNodeFactory.instance.arrayNode();
        for (HeldCredential credential : credentialStore.findAll()) {
            ObjectNode node = JsonNodeFactory.instance.objectNode();
            node.put("format", credential.format().identifier());
            JsonNode claims = credential.claimsView();
            node.set("claims", claims);
            array.add(node);
        }
        return array.toString();
    }

    /**
     * Fetches an Authorization Request from {@code verifierAuthorizeUrl} (e.g.
     * {@code oid4vp-demo-verifier}'s {@code /oid4vp/authorize/demo}), evaluates its DCQL query against
     * the credentials held in {@link #credentialStore}, and POSTs the resulting {@code vp_token} to the
     * request's {@code response_uri} — for a {@code direct_post.jwt} registration, encrypts the response
     * instead of posting it in the clear. See {@code oid4vp-demo-wallet}'s own {@code WalletController}
     * for the reference implementation this mirrors.
     */
    @PostMapping(value = "/present", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> present(@RequestBody PresentRequest body) throws Exception {
        log.info("Fetching Authorization Request from {}", body.verifierAuthorizeUrl());
        String requestJson = restClient.get().uri(body.verifierAuthorizeUrl()).retrieve().body(String.class);
        JsonNode request = MAPPER.readTree(requestJson);

        JsonNode expectedAudience = request.get("expected_response_audience");
        String audience = expectedAudience != null && !expectedAudience.isNull()
                ? expectedAudience.asText() : request.get("client_id").asText();
        String clientId = request.get("client_id").asText();
        String nonce = request.get("nonce").asText();
        String state = request.get("state").asText();
        String responseUri = request.get("response_uri").asText();
        DcqlQuery dcqlQuery = DcqlQueryReader.read(request.get("dcql_query"));

        String responseMode = request.hasNonNull("response_mode") ? request.get("response_mode").asText() : "direct_post";
        boolean encryptedResponse = responseMode.endsWith(".jwt");
        ClientMetadata clientMetadata = encryptedResponse ? ClientMetadataReader.read(request.get("client_metadata")) : null;
        Optional<JsonNode> responseEncryptionPublicJwk = encryptedResponse
                ? Optional.of(resolveResponseEncryptionPublicJwk(clientMetadata))
                : Optional.empty();

        WalletAuthorizationResponseBuilder builder = new WalletAuthorizationResponseBuilder(Map.of(
                CredentialFormat.DC_SD_JWT, (PresentationBuilder) new SdJwtVcPresentationBuilderAdapter(),
                CredentialFormat.MSO_MDOC, new MdocPresentationBuilderAdapter()));

        HolderKeyResolver holderKeyResolver = new HolderKeyResolver() {
            @Override
            public Optional<JWSSigner> resolveSigner(HeldCredential credential) {
                return credentialStore.bindingKeyFor(credential).map(bindingKey -> {
                    try {
                        return (JWSSigner) new ECDSASigner(bindingKey);
                    } catch (JOSEException e) {
                        throw new IllegalStateException(e);
                    }
                });
            }

            @Override
            public Optional<PrivateKey> resolvePrivateKey(HeldCredential credential) {
                return credentialStore.bindingKeyFor(credential).map(bindingKey -> {
                    try {
                        return (PrivateKey) bindingKey.toECPrivateKey();
                    } catch (JOSEException e) {
                        throw new IllegalStateException(e);
                    }
                });
            }
        };

        WalletAuthorizationResponseResult result = builder.build(
                dcqlQuery, credentialStore,
                new PresentationBuildParams(
                        nonce, audience, clientId, responseUri, responseEncryptionPublicJwk, holderKeyResolver, Clock.systemUTC()));

        if (result instanceof WalletAuthorizationResponseResult.Declined declined) {
            log.warn("Declining: {}", declined.reason());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("{\"error\":\"access_denied\",\"reason\":\"" + declined.reason() + "\"}");
        }

        VpToken vpToken = ((WalletAuthorizationResponseResult.Built) result).vpToken();
        String vpTokenJson = MAPPER.writeValueAsString(VpTokenWriter.write(vpToken));
        log.info("Posting vp_token to {}", responseUri);

        String formBody = encryptedResponse
                ? "response=" + URLEncoder.encode(buildEncryptedResponse(clientMetadata, vpTokenJson, state), StandardCharsets.UTF_8)
                : "vp_token=" + URLEncoder.encode(vpTokenJson, StandardCharsets.UTF_8)
                        + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

        String verifierResponse = restClient.post()
                .uri(responseUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formBody)
                .retrieve()
                .body(String.class);

        log.info("Verifier responded: {}", verifierResponse);
        return ResponseEntity.ok(verifierResponse);
    }

    private String buildEncryptedResponse(ClientMetadata clientMetadata, String vpTokenJson, String state) throws Exception {
        JsonNode jwks = clientMetadata.jwks()
                .orElseThrow(() -> new IllegalStateException("direct_post.jwt requires client_metadata.jwks"));

        ObjectNode payload = MAPPER.createObjectNode();
        payload.set("vp_token", MAPPER.readTree(vpTokenJson));
        payload.put("state", state);

        return ResponseEncryptor.encrypt(payload, jwks, clientMetadata.encryptedResponseEncValuesSupportedOrDefault());
    }

    private JsonNode resolveResponseEncryptionPublicJwk(ClientMetadata clientMetadata) {
        JsonNode jwks = clientMetadata.jwks()
                .orElseThrow(() -> new IllegalStateException("direct_post.jwt requires client_metadata.jwks"));
        JsonNode keys = jwks.get("keys");
        if (keys == null || !keys.isArray() || keys.isEmpty()) {
            throw new IllegalStateException("client_metadata.jwks has no keys");
        }
        return keys.get(0);
    }

    public record PresentRequest(String verifierAuthorizeUrl) {}
}
