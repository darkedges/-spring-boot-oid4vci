package com.darkedges.oid4vci.wallet;

import com.darkedges.oid4vci.core.credential.CredentialRequest;
import com.darkedges.oid4vci.core.credential.CredentialResponse;
import com.darkedges.oid4vci.core.credential.IssuedCredential;
import com.darkedges.oid4vci.core.metadata.ClaimDescription;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.MsoMdocCredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.Grants;
import com.darkedges.oid4vci.core.offer.PreAuthorizedCodeGrant;
import com.darkedges.oid4vci.core.token.TokenResponse;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.InMemoryIssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.InMemoryPreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.MsoMdocCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.NonceService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A no-HTTP round trip: feeds real {@code oid4vci-issuer-core} services directly as the transport
 * implementations (test-scope dependency, mirroring {@code oid4vp-wallet-core}'s own test-scope
 * dependency on {@code oid4vp-verifier-core}), driving the full protocol for both credential formats in
 * one JVM and asserting the resulting {@link HeldCredential}s carry the claims that were actually issued.
 */
class WalletIssuanceOrchestratorTest {

    private static final URI CREDENTIAL_ISSUER = URI.create("https://issuer.example.org");
    private static final URI TOKEN_ENDPOINT = URI.create("https://issuer.example.org/token");
    private static final URI NONCE_ENDPOINT = URI.create("https://issuer.example.org/nonce");
    private static final URI CREDENTIAL_ENDPOINT = URI.create("https://issuer.example.org/credential");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void obtainsBothFormatsFromOneCredentialOfferAndParsesThemViaOid4vpsOwnFormatModules() throws Exception {
        ECKey sdJwtIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("sd-jwt-issuer-1").generate();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair mdocIssuerKeyPair = generator.generateKeyPair();

        PreAuthorizedCodeStore codeStore = new InMemoryPreAuthorizedCodeStore();
        PreAuthorizedCodeService codeService = new PreAuthorizedCodeService(codeStore, CLOCK);
        NonceService nonceService = new NonceService(new InMemoryNonceStore(), CLOCK, Duration.ofMinutes(5));
        AccessTokenService accessTokenService = new AccessTokenService(sdJwtIssuerKey, CREDENTIAL_ISSUER.toString(), Duration.ofMinutes(5), CLOCK);
        IssuedAccessTokenClaimsStore claimsStore = new InMemoryIssuedAccessTokenClaimsStore();
        ProofOfPossessionValidator proofValidator = new ProofOfPossessionValidator(nonceService, CLOCK, Duration.ofMinutes(5));
        SdJwtVcCredentialIssuanceService sdJwtIssuance = new SdJwtVcCredentialIssuanceService(
                sdJwtIssuerKey, CREDENTIAL_ISSUER.toString(), List.of(), Duration.ofDays(365), CLOCK);
        MsoMdocCredentialIssuanceService mdocIssuance = new MsoMdocCredentialIssuanceService(
                mdocIssuerKeyPair.getPrivate(), List.of(), Duration.ofDays(365), CLOCK);

        Map<String, CredentialConfiguration> configurations = Map.of(
                "UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://issuer.example.org/vct/UniversityDegree", List.of(), Map.of(), List.of(), List.of()),
                "org.iso.18013.5.1.mDL", new MsoMdocCredentialConfiguration(
                        "org.iso.18013.5.1.mDL",
                        List.of(new ClaimDescription(ClaimsPathPointer.of("org.iso.18013.5.1", "given_name"), Optional.empty()),
                                new ClaimDescription(ClaimsPathPointer.of("org.iso.18013.5.1", "family_name"), Optional.of(true))),
                        Map.of(), List.of(), List.of()));

        CredentialIssuerMetadata metadata = new CredentialIssuerMetadata(
                CREDENTIAL_ISSUER, CREDENTIAL_ENDPOINT, Optional.of(NONCE_ENDPOINT), Optional.empty(), List.of(), configurations);

        codeStore.save("the-code", new PreAuthorizedCodeSession(
                List.of("UniversityDegreeCredential", "org.iso.18013.5.1.mDL"), Optional.empty(),
                Map.of("given_name", "Jane", "family_name", "Doe"), NOW.plus(Duration.ofMinutes(10))));

        CredentialOffer offer = new CredentialOffer(
                CREDENTIAL_ISSUER, List.of("UniversityDegreeCredential", "org.iso.18013.5.1.mDL"),
                Optional.of(new Grants(Optional.empty(), Optional.of(new PreAuthorizedCodeGrant("the-code", Optional.empty(), Optional.empty())))));

        ECKey holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder-1").generate();
        WalletIssuanceOrchestrator orchestrator = new WalletIssuanceOrchestrator(
                new InProcessTokenClient(codeService, accessTokenService, claimsStore),
                new InProcessNonceClient(nonceService),
                new InProcessCredentialClient(accessTokenService, proofValidator, claimsStore, configurations, sdJwtIssuance, mdocIssuance),
                configurationId -> holderKey,
                CLOCK);

        List<HolderBoundCredential> obtained = orchestrator.obtainCredentials(offer, metadata, TOKEN_ENDPOINT, Optional::empty);

        assertThat(obtained).hasSize(2);
        assertThat(obtained).allSatisfy(c -> assertThat(c.bindingKey()).isEqualTo(holderKey));
        List<HeldCredential> heldCredentials = obtained.stream().map(HolderBoundCredential::credential).toList();
        SdJwtVcHeldCredential sdJwt = (SdJwtVcHeldCredential) heldCredentials.stream()
                .filter(SdJwtVcHeldCredential.class::isInstance).findFirst().orElseThrow();
        assertThat(sdJwt.claimsView().get("given_name").asText()).isEqualTo("Jane");
        assertThat(sdJwt.claimsView().get("family_name").asText()).isEqualTo("Doe");

        MdocHeldCredential mdoc = (MdocHeldCredential) heldCredentials.stream()
                .filter(MdocHeldCredential.class::isInstance).findFirst().orElseThrow();
        assertThat(mdoc.claimsView().get("org.iso.18013.5.1").get("given_name").asText()).isEqualTo("Jane");
        assertThat(mdoc.claimsView().get("org.iso.18013.5.1").get("family_name").asText()).isEqualTo("Doe");
    }

    /** In-process stand-in for a real Token Endpoint HTTP call: drives {@code oid4vci-issuer-core}'s own
     * services directly instead of going over the wire, including the claims-store bookkeeping a real
     * TokenController must do (see {@link AccessTokenService#issue}'s Javadoc). */
    private record InProcessTokenClient(
            PreAuthorizedCodeService codeService, AccessTokenService accessTokenService, IssuedAccessTokenClaimsStore claimsStore)
            implements PreAuthorizedTokenEndpointClient {

        @Override
        public TokenResponse exchange(URI tokenEndpoint, String preAuthorizedCode, Optional<String> txCode) {
            PreAuthorizedCodeSession session = codeService.redeem(
                    new com.darkedges.oid4vci.core.token.PreAuthorizedCodeTokenRequest(preAuthorizedCode, txCode));
            AccessTokenService.IssuedAccessToken issued = accessTokenService.issue(session);
            claimsStore.save(issued.subject(), session.claims());
            return issued.tokenResponse();
        }
    }

    private record InProcessNonceClient(NonceService nonceService) implements NonceEndpointClient {

        @Override
        public String fetchNonce(URI nonceEndpoint) {
            return nonceService.issue();
        }
    }

    /** In-process stand-in for a real Credential Endpoint HTTP call: verifies the access token and proof
     * exactly like a real Credential Endpoint handler would, then dispatches to the matching
     * {@code CredentialIssuanceService}. */
    private record InProcessCredentialClient(
            AccessTokenService accessTokenService, ProofOfPossessionValidator proofValidator,
            IssuedAccessTokenClaimsStore claimsStore, Map<String, CredentialConfiguration> configurations,
            SdJwtVcCredentialIssuanceService sdJwtIssuance, MsoMdocCredentialIssuanceService mdocIssuance)
            implements CredentialEndpointClient {

        @Override
        public CredentialResponse request(URI credentialEndpoint, String accessToken, CredentialRequest request) {
            AccessTokenService.AccessTokenClaims tokenClaims = accessTokenService.verify(accessToken);
            String proofJwt = request.proofs().flatMap(p -> p.jwt()).orElseThrow().get(0);
            ECKey holderKey = proofValidator.verify(proofJwt, CREDENTIAL_ISSUER.toString());

            String configurationId = request.credentialConfigurationId().orElseThrow();
            CredentialConfiguration configuration = configurations.get(configurationId);
            Map<String, String> claims = claimsStore.find(tokenClaims.subject()).orElseThrow();

            String raw = switch (configuration) {
                case SdJwtVcCredentialConfiguration ignored -> sdJwtIssuance.issue(configuration, claims, holderKey);
                case MsoMdocCredentialConfiguration ignored -> mdocIssuance.issue(configuration, claims, holderKey);
            };

            return new CredentialResponse(Optional.of(List.of(new IssuedCredential(raw))), Optional.empty());
        }
    }
}
