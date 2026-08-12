package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.credential.CredentialRequest;
import com.darkedges.oid4vci.core.credential.CredentialRequestReader;
import com.darkedges.oid4vci.core.credential.CredentialResponse;
import com.darkedges.oid4vci.core.credential.CredentialResponseWriter;
import com.darkedges.oid4vci.core.credential.IssuedCredential;
import com.darkedges.oid4vci.core.credential.Proofs;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.BatchCredentialIssuance;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Clock;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Credential Endpoint (OID4VCI 1.0, Section 8) — the one endpoint in this project that's actually
 * behind {@code oauth2ResourceServer()}: the {@link Jwt} principal is Spring Security's own, already
 * signature/expiry-verified by the app's configured {@code JwtDecoder} before this method ever runs (see
 * the project README for why that's the right tool here rather than a custom {@code AuthenticationProvider}).
 * A DPoP-bound access token (one minted with a {@code cnf.jkt} claim — see {@code TokenController}) is
 * also fully handled before this method runs: Spring Security 7.1's native {@code .dPoP(...)}
 * resource-server support (wired in the consuming app's {@code SecurityConfig}) verifies the request's
 * {@code DPoP} proof against the token's {@code cnf.jkt} and rejects a mismatched/missing one itself —
 * confirmed live that a hand-rolled equivalent check in this controller never even ran, since
 * {@code BearerTokenAuthenticationFilter} already refuses a {@code cnf}-bearing JWT presented without a
 * matching DPoP proof before dispatch. This handler's own job starts one layer in: read the authorized
 * {@code credential_configuration_ids} off the token, verify each proof of possession the request
 * carries — more than one only if the Issuer Metadata advertises {@code batch_credential_issuance} (see
 * {@code BatchCredentialIssuance}), one Credential minted per proof, all against the same claim values —
 * look up the claim values persisted at token mint time ({@link TokenController}), and dispatch to the
 * matching {@link CredentialIssuanceService}. Returns a pre-serialized {@code String} — see
 * {@link IssuerMetadataController}'s Javadoc for why. The request body is read the same way, for the same
 * reason: a Jackson-2 {@code JsonNode} isn't something the Jackson-3 message converter Spring Boot 4.1
 * also registers knows how to construct, so the raw body is read as a {@code String} and parsed manually
 * with this module's own Jackson-2 {@link ObjectMapper} rather than via {@code @RequestBody JsonNode}
 * directly (confirmed live: this was the second half of the same Jackson 2/3 coexistence issue — the
 * write side failed first, then this).
 */
@RestController
public class CredentialController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CredentialIssuerMetadataTemplate template;
    private final ProofOfPossessionValidator proofValidator;
    private final IssuedAccessTokenClaimsStore claimsStore;
    private final Map<CredentialFormat, CredentialIssuanceService> issuanceServices;
    private final Clock clock;

    public CredentialController(
            CredentialIssuerMetadataTemplate template, ProofOfPossessionValidator proofValidator,
            IssuedAccessTokenClaimsStore claimsStore, Map<CredentialFormat, CredentialIssuanceService> issuanceServices) {
        this(template, proofValidator, claimsStore, issuanceServices, Clock.systemUTC());
    }

    public CredentialController(
            CredentialIssuerMetadataTemplate template, ProofOfPossessionValidator proofValidator,
            IssuedAccessTokenClaimsStore claimsStore, Map<CredentialFormat, CredentialIssuanceService> issuanceServices,
            Clock clock) {
        this.template = template;
        this.proofValidator = proofValidator;
        this.claimsStore = claimsStore;
        this.issuanceServices = issuanceServices;
        this.clock = clock;
    }

    @PostMapping(value = "/credential", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> credential(
            @AuthenticationPrincipal Jwt accessToken, @RequestBody String rawBody, HttpServletRequest servletRequest) {
        String baseUrl = RequestBaseUrl.resolve(servletRequest);
        CredentialIssuerMetadata metadata = template.resolve(baseUrl);
        JsonNode body;
        try {
            body = MAPPER.readTree(rawBody);
        } catch (Exception e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_REQUEST, "request body is not valid JSON", e);
        }
        CredentialRequest request = CredentialRequestReader.read(body);

        String configurationId = request.credentialConfigurationId()
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_REQUEST,
                        "credential_identifier is not supported in this phase; use credential_configuration_id"));

        List<String> authorizedConfigurationIds = accessToken.getClaimAsStringList("credential_configuration_ids");
        if (authorizedConfigurationIds == null || !authorizedConfigurationIds.contains(configurationId)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_REQUEST,
                    "access token is not authorized for credential_configuration_id: " + configurationId);
        }

        CredentialConfiguration configuration = metadata.credentialConfigurationsSupported().get(configurationId);
        if (configuration == null) {
            throw new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_CREDENTIAL_TYPE,
                    "unknown credential_configuration_id: " + configurationId);
        }

        List<String> proofJwts = request.proofs().flatMap(Proofs::jwt).orElse(List.of());
        if (proofJwts.isEmpty()) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proofs.jwt is required");
        }
        int maxBatchSize = metadata.batchCredentialIssuance().map(BatchCredentialIssuance::batchSize).orElse(1);
        if (proofJwts.size() > maxBatchSize) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CREDENTIAL_REQUEST,
                    "proofs.jwt has " + proofJwts.size() + " entries, exceeding this issuer's batch_size of " + maxBatchSize);
        }

        // Expiry is enforced by the store, so an expired entry is indistinguishable from an absent
        // one here -- which is right: both mean this token authorizes nothing. The token's own exp is
        // checked by the resource server long before this point; this guards the claims themselves,
        // which for a real issuer are somebody's passport details and should not outlive their use.
        Map<String, String> claims = claimsStore.find(accessToken.getSubject(), clock.instant())
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "no claims on file for this access token"));

        CredentialIssuanceService issuanceService = issuanceServices.get(configuration.format());
        if (issuanceService == null) {
            throw new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT,
                    "no issuance service registered for format: " + configuration.format());
        }

        List<IssuedCredential> issued = new ArrayList<>();
        for (String proofJwt : proofJwts) {
            ECKey holderKey = proofValidator.verify(proofJwt, metadata.credentialIssuer().toString());
            issued.add(new IssuedCredential(issuanceService.issue(configuration, claims, holderKey, baseUrl)));
        }

        CredentialResponse response = new CredentialResponse(Optional.of(issued), Optional.empty());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(CredentialResponseWriter.write(response).toString());
    }
}
