package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.credential.CredentialRequest;
import com.darkedges.oid4vci.core.credential.CredentialRequestReader;
import com.darkedges.oid4vci.core.credential.CredentialResponse;
import com.darkedges.oid4vci.core.credential.CredentialResponseWriter;
import com.darkedges.oid4vci.core.credential.IssuedCredential;
import com.darkedges.oid4vci.core.credential.Proofs;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Credential Endpoint (OID4VCI 1.0, Section 8) — the one endpoint in this project that's actually
 * behind {@code oauth2ResourceServer()}: the {@link Jwt} principal is Spring Security's own, already
 * signature/expiry-verified by the app's configured {@code JwtDecoder} before this method ever runs (see
 * the project README for why that's the right tool here rather than a custom {@code AuthenticationProvider}).
 * This handler's own job starts one layer in: read the authorized {@code credential_configuration_ids}
 * off the token, verify the request's proof of possession, look up the claim values persisted at token
 * mint time ({@link TokenController}), and dispatch to the matching {@link CredentialIssuanceService}.
 * Returns a pre-serialized {@code String} — see {@link IssuerMetadataController}'s Javadoc for why. The
 * request body is read the same way, for the same reason: a Jackson-2 {@code JsonNode} isn't something
 * the Jackson-3 message converter Spring Boot 4.1 also registers knows how to construct, so the raw
 * body is read as a {@code String} and parsed manually with this module's own Jackson-2 {@link ObjectMapper}
 * rather than via {@code @RequestBody JsonNode} directly (confirmed live: this was the second half of the
 * same Jackson 2/3 coexistence issue — the write side failed first, then this).
 */
@RestController
public class CredentialController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CredentialIssuerMetadata metadata;
    private final ProofOfPossessionValidator proofValidator;
    private final IssuedAccessTokenClaimsStore claimsStore;
    private final Map<CredentialFormat, CredentialIssuanceService> issuanceServices;

    public CredentialController(
            CredentialIssuerMetadata metadata, ProofOfPossessionValidator proofValidator,
            IssuedAccessTokenClaimsStore claimsStore, Map<CredentialFormat, CredentialIssuanceService> issuanceServices) {
        this.metadata = metadata;
        this.proofValidator = proofValidator;
        this.claimsStore = claimsStore;
        this.issuanceServices = issuanceServices;
    }

    @PostMapping(value = "/credential", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> credential(@AuthenticationPrincipal Jwt accessToken, @RequestBody String rawBody) {
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

        String proofJwt = request.proofs()
                .flatMap(Proofs::jwt)
                .flatMap(list -> list.stream().findFirst())
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proofs.jwt is required"));
        ECKey holderKey = proofValidator.verify(proofJwt, metadata.credentialIssuer().toString());

        Map<String, String> claims = claimsStore.find(accessToken.getSubject())
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "no claims on file for this access token"));

        CredentialIssuanceService issuanceService = issuanceServices.get(configuration.format());
        if (issuanceService == null) {
            throw new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT,
                    "no issuance service registered for format: " + configuration.format());
        }
        String issued = issuanceService.issue(configuration, claims, holderKey);

        CredentialResponse response = new CredentialResponse(
                Optional.of(List.of(new IssuedCredential(issued))), Optional.empty());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(CredentialResponseWriter.write(response).toString());
    }
}
