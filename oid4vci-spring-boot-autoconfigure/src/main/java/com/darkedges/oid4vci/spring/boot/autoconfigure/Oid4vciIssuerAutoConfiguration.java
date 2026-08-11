package com.darkedges.oid4vci.spring.boot.autoconfigure;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.BatchCredentialIssuance;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataReader;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.AttestationChallengeService;
import com.darkedges.oid4vci.issuer.AuthorizationClaimsResolver;
import com.darkedges.oid4vci.issuer.AuthorizationCodeService;
import com.darkedges.oid4vci.issuer.AuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.ClientAttestationTrustAnchor;
import com.darkedges.oid4vci.issuer.ClientAttestationValidator;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import com.darkedges.oid4vci.issuer.DpopProofValidator;
import com.darkedges.oid4vci.issuer.DpopReplayStore;
import com.darkedges.oid4vci.issuer.InMemoryAuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.InMemoryCredentialOfferStore;
import com.darkedges.oid4vci.issuer.InMemoryDpopReplayStore;
import com.darkedges.oid4vci.issuer.InMemoryIssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.InMemoryNonceStore;
import com.darkedges.oid4vci.issuer.InMemoryPreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.MsoMdocCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.NonceService;
import com.darkedges.oid4vci.issuer.NonceStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vci.issuer.InMemoryPushedAuthorizationRequestStore;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.web.AuthorizationEndpointController;
import com.darkedges.oid4vci.issuer.web.AuthorizationServerMetadataController;
import com.darkedges.oid4vci.issuer.web.ChallengeController;
import com.darkedges.oid4vci.issuer.web.CredentialController;
import com.darkedges.oid4vci.issuer.web.CredentialOfferController;
import com.darkedges.oid4vci.issuer.web.IssuerMetadataController;
import com.darkedges.oid4vci.issuer.web.JwksController;
import com.darkedges.oid4vci.issuer.web.NonceController;
import com.darkedges.oid4vci.issuer.web.Oid4vciExceptionHandler;
import com.darkedges.oid4vci.issuer.web.PushedAuthorizationRequestController;
import com.darkedges.oid4vci.issuer.web.SdJwtVcTypeMetadataController;
import com.darkedges.oid4vci.issuer.web.TokenController;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Auto-configures the supporting beans for an Issuer using {@code oid4vci-issuer-web}'s controllers: the
 * Credential Issuer Metadata document and in-memory stores from {@code oid4vci.issuer.*} properties, the
 * proof/nonce/token services, and (only once the consuming app supplies the necessary signing key
 * beans — see below) the per-format {@link CredentialIssuanceService}s and a {@link JwtDecoder} routed
 * through this issuer's own {@link JwksController}.
 *
 * <p>This does <em>not</em> auto-apply {@code oauth2ResourceServer()} to any {@code HttpSecurity} — the
 * consuming application's own {@code SecurityFilterChain @Bean} does that explicitly, same restraint as
 * oid4vp's autoconfiguration never auto-applying {@code Oid4vpLoginConfigurer}. An issuer signing
 * {@link ECKey} (used for access-token minting, SD-JWT VC credential signing, and the JWKS endpoint) and
 * an {@link MdocIssuerKeyMaterial} (for mdoc credential signing) are deliberately not provided here
 * either — "who signs on your behalf" is inherently deployment-specific, exactly like oid4vp never
 * auto-providing an {@code IssuerKeyResolver}. The beans that need them ({@link AccessTokenService},
 * {@link JwksController}, the per-format issuance services, the {@link JwtDecoder}) are only registered
 * once the app supplies the corresponding key bean(s) — omitting them entirely leaves that slice of the
 * issuer unwired rather than failing the whole context, so an app that only wants one credential format
 * doesn't have to fabricate key material for the other.
 */
@AutoConfiguration
@EnableConfigurationProperties(Oid4vciIssuerProperties.class)
@ConditionalOnClass(IssuerMetadataController.class)
public class Oid4vciIssuerAutoConfiguration {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Bean
    @ConditionalOnMissingBean
    public CredentialIssuerMetadataTemplate credentialIssuerMetadataTemplate(Oid4vciIssuerProperties properties) {
        JsonNode configurations = parseJson(properties.getCredentialConfigurationsSupported(),
                "oid4vci.issuer.credential-configurations-supported");
        ObjectNode root = MAPPER.createObjectNode();
        root.set("credential_configurations_supported", configurations);
        Optional<BatchCredentialIssuance> batchCredentialIssuance = properties.getBatchCredentialIssuanceMaxSize() == null
                ? Optional.empty() : Optional.of(new BatchCredentialIssuance(properties.getBatchCredentialIssuanceMaxSize()));
        return new CredentialIssuerMetadataTemplate(
                properties.getCredentialEndpointPath(), Optional.of(properties.getNonceEndpointPath()),
                CredentialIssuerMetadataReader.readConfigurationsSupported(root), batchCredentialIssuance);
    }

    @Bean
    @ConditionalOnMissingBean
    public PreAuthorizedCodeStore preAuthorizedCodeStore() {
        return new InMemoryPreAuthorizedCodeStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationCodeStore authorizationCodeStore() {
        return new InMemoryAuthorizationCodeStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public PushedAuthorizationRequestStore pushedAuthorizationRequestStore() {
        return new InMemoryPushedAuthorizationRequestStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public NonceStore nonceStore() {
        return new InMemoryNonceStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public IssuedAccessTokenClaimsStore issuedAccessTokenClaimsStore() {
        return new InMemoryIssuedAccessTokenClaimsStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public CredentialOfferStore credentialOfferStore() {
        return new InMemoryCredentialOfferStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public PreAuthorizedCodeService preAuthorizedCodeService(PreAuthorizedCodeStore store) {
        return new PreAuthorizedCodeService(store, Clock.systemUTC());
    }

    /** Only registered once the consuming app supplies an {@link AuthorizationClaimsResolver} bean — see
     * that interface's Javadoc for why the {@code authorization_code} grant is entirely gated on it. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthorizationClaimsResolver.class)
    public AuthorizationCodeService authorizationCodeService(AuthorizationCodeStore store) {
        return new AuthorizationCodeService(store, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    public NonceService nonceService(NonceStore store, Oid4vciIssuerProperties properties) {
        return new NonceService(store, Clock.systemUTC(), properties.getNonceTtl());
    }

    @Bean
    @ConditionalOnMissingBean
    public ProofOfPossessionValidator proofOfPossessionValidator(NonceService nonceService, Oid4vciIssuerProperties properties) {
        return new ProofOfPossessionValidator(nonceService, Clock.systemUTC(), properties.getProofClockSkew());
    }

    @Bean
    @ConditionalOnMissingBean
    public DpopReplayStore dpopReplayStore() {
        return new InMemoryDpopReplayStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public DpopProofValidator dpopProofValidator(DpopReplayStore dpopReplayStore, Oid4vciIssuerProperties properties) {
        return new DpopProofValidator(dpopReplayStore, Clock.systemUTC(), properties.getDpopProofFreshness());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public AccessTokenService accessTokenService(ECKey issuerSigningKey, Oid4vciIssuerProperties properties) {
        return new AccessTokenService(issuerSigningKey, properties.getAccessTokenTtl(), Clock.systemUTC());
    }

    /**
     * Built from an in-memory {@link JWKSource} wrapping this issuer's own public key, not
     * {@code NimbusJwtDecoder.withJwkSetUri(...)} — the latter would need a URL to fetch the JWKS from,
     * but this decoder verifies tokens minted by this very app, so making it fetch its own JWKS back over
     * HTTP would need yet another "what's my own address" config value (the same problem
     * {@link #credentialIssuerMetadataTemplate}/{@link RequestBaseUrl} exist to avoid) for no benefit.
     *
     * <p>{@code jwsAlgorithm(ES256)} is required regardless of the source: this issuer signs access
     * tokens with ES256 throughout (see {@link AccessTokenService}), and a decoder built without it only
     * trusts RS256 by default, rejecting every token with "Another algorithm expected" (confirmed live:
     * this was missing on the first real end-to-end run against a live demo issuer and every Credential
     * Request failed with 401 until it was added).
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public JwtDecoder jwtDecoder(ECKey issuerSigningKey) {
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(issuerSigningKey.toPublicJWK()));
        return NimbusJwtDecoder.withJwkSource(jwkSource)
                .jwsAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.ES256)
                .build();
    }

    @Bean(name = "sdJwtVcCredentialIssuanceService")
    @ConditionalOnMissingBean(name = "sdJwtVcCredentialIssuanceService")
    @ConditionalOnBean(ECKey.class)
    public CredentialIssuanceService sdJwtVcCredentialIssuanceService(ECKey issuerSigningKey, Oid4vciIssuerProperties properties) {
        List<String> certificateChain = issuerSigningKey.getX509CertChain() == null
                ? List.of()
                : issuerSigningKey.getX509CertChain().stream().map(Object::toString).toList();
        return new SdJwtVcCredentialIssuanceService(
                issuerSigningKey, certificateChain, properties.getCredentialValidity(), Clock.systemUTC());
    }

    @Bean(name = "mdocCredentialIssuanceService")
    @ConditionalOnMissingBean(name = "mdocCredentialIssuanceService")
    @ConditionalOnBean(MdocIssuerKeyMaterial.class)
    public CredentialIssuanceService mdocCredentialIssuanceService(MdocIssuerKeyMaterial keyMaterial, Oid4vciIssuerProperties properties) {
        return new MsoMdocCredentialIssuanceService(
                keyMaterial.privateKey(), keyMaterial.certificateChain(), properties.getCredentialValidity(), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    public Map<CredentialFormat, CredentialIssuanceService> credentialIssuanceServices(
            ObjectProvider<CredentialIssuanceService> services) {
        Map<CredentialFormat, CredentialIssuanceService> byFormat = new HashMap<>();
        services.forEach(service -> byFormat.put(service.format(), service));
        return Map.copyOf(byFormat);
    }

    /**
     * {@code @RestControllerAdvice} beans are only ever discovered by component scanning, but this one
     * lives in {@code oid4vci-issuer-web}'s package, not the consuming app's — same reason every
     * controller below is an explicit {@code @Bean} rather than left to component scanning. Missing this
     * one is exactly the kind of bug that only surfaces in a real HTTP response: confirmed live that
     * without it, a Token Endpoint {@link com.darkedges.oid4vci.core.error.Oid4vciException} (e.g. a
     * failed Client Attestation check) propagated all the way to Tomcat's default error page — still the
     * right HTTP status by coincidence (Spring Security's own exception handling happened to pass it
     * through), but with an empty body instead of the {@code {"error": "..."}} JSON OID4VCI clients
     * expect.
     */
    @Bean
    @ConditionalOnMissingBean
    public Oid4vciExceptionHandler oid4vciExceptionHandler(NonceService nonceService) {
        return new Oid4vciExceptionHandler(nonceService);
    }

    @Bean
    @ConditionalOnMissingBean
    public IssuerMetadataController issuerMetadataController(CredentialIssuerMetadataTemplate template) {
        return new IssuerMetadataController(template);
    }

    @Bean
    @ConditionalOnMissingBean
    public SdJwtVcTypeMetadataController sdJwtVcTypeMetadataController(CredentialIssuerMetadataTemplate template) {
        return new SdJwtVcTypeMetadataController(template);
    }

    @Bean
    @ConditionalOnMissingBean
    public CredentialOfferController credentialOfferController(CredentialOfferStore store) {
        return new CredentialOfferController(store);
    }

    @Bean
    @ConditionalOnMissingBean
    public NonceController nonceController(NonceService nonceService) {
        return new NonceController(nonceService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public TokenController tokenController(
            PreAuthorizedCodeService preAuthorizedCodeService, AccessTokenService accessTokenService,
            IssuedAccessTokenClaimsStore claimsStore, DpopProofValidator dpopProofValidator,
            ObjectProvider<ClientAttestationValidator> clientAttestationValidator,
            ObjectProvider<AuthorizationCodeService> authorizationCodeService) {
        return new TokenController(
                preAuthorizedCodeService, accessTokenService, claimsStore, dpopProofValidator,
                Optional.ofNullable(clientAttestationValidator.getIfAvailable()),
                Optional.ofNullable(authorizationCodeService.getIfAvailable()));
    }

    /** Only registered once the consuming app supplies an {@link AuthorizationClaimsResolver} bean — see
     * that interface's Javadoc. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({ECKey.class, AuthorizationClaimsResolver.class})
    public AuthorizationEndpointController authorizationEndpointController(
            AuthorizationCodeStore authorizationCodeStore, PushedAuthorizationRequestStore pushedAuthorizationRequestStore,
            CredentialIssuerMetadataTemplate template, AuthorizationClaimsResolver claimsResolver) {
        return new AuthorizationEndpointController(
                authorizationCodeStore, pushedAuthorizationRequestStore, template, claimsResolver);
    }

    /** Only registered once the consuming app supplies an {@link AuthorizationClaimsResolver} bean — a PAR
     * endpoint with no Authorization Endpoint able to redeem its {@code request_uri} would be pointless. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({ECKey.class, AuthorizationClaimsResolver.class})
    public PushedAuthorizationRequestController pushedAuthorizationRequestController(
            PushedAuthorizationRequestStore pushedAuthorizationRequestStore) {
        return new PushedAuthorizationRequestController(pushedAuthorizationRequestStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public CredentialController credentialController(
            CredentialIssuerMetadataTemplate template, ProofOfPossessionValidator proofValidator, IssuedAccessTokenClaimsStore claimsStore,
            Map<CredentialFormat, CredentialIssuanceService> issuanceServices) {
        return new CredentialController(template, proofValidator, claimsStore, issuanceServices);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public JwksController jwksController(ECKey issuerSigningKey) {
        return new JwksController(issuerSigningKey);
    }

    /** A separate {@link DpopReplayStore} instance from {@link #dpopReplayStore} — same generic
     * single-use-{@code jti} bookkeeping, but a distinct jti namespace (Client Attestation PoP JWTs vs.
     * DPoP proofs must never be checked against each other's replay history). */
    @Bean
    @ConditionalOnMissingBean
    public DpopReplayStore clientAttestationPopReplayStore() {
        return new InMemoryDpopReplayStore();
    }

    /**
     * Builds a {@link ClientAttestationTrustAnchor} straight from {@code oid4vci.issuer.*} properties, so
     * enabling {@code attest_jwt_client_auth} doesn't require a consuming app to write any Java — only
     * registered when both properties are set (an app that needs something more dynamic, e.g. trusting
     * more than one Wallet Provider, can still supply its own {@code ClientAttestationTrustAnchor} bean
     * directly, which backs this one off via {@code @ConditionalOnMissingBean}).
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "oid4vci.issuer",
            name = {"client-attestation-trusted-issuer", "client-attestation-trusted-issuer-key"})
    public ClientAttestationTrustAnchor clientAttestationTrustAnchor(Oid4vciIssuerProperties properties) throws java.text.ParseException {
        return new ClientAttestationTrustAnchor(
                properties.getClientAttestationTrustedIssuer(),
                ECKey.parse(properties.getClientAttestationTrustedIssuerKey()));
    }

    /** Only registered once {@code oid4vci.issuer.attestation-challenge-endpoint-path} is set — see that
     * property's Javadoc for why this feature defaults to off. A fresh {@code InMemoryNonceStore} is
     * constructed inline here, rather than exposed as its own {@code NonceStore} bean like {@link #nonceStore}:
     * {@link #nonceService} already injects a {@code NonceStore} by an unqualified parameter name, and a
     * second bean of that same type would leave Spring unable to tell them apart. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "oid4vci.issuer", name = "attestation-challenge-endpoint-path")
    public AttestationChallengeService attestationChallengeService(Oid4vciIssuerProperties properties) {
        return new AttestationChallengeService(
                new NonceService(new InMemoryNonceStore(), Clock.systemUTC(), properties.getNonceTtl()));
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AttestationChallengeService.class)
    public ChallengeController challengeController(AttestationChallengeService attestationChallengeService) {
        return new ChallengeController(attestationChallengeService);
    }

    /** Only registered once the consuming app supplies a {@link ClientAttestationTrustAnchor} bean — the
     * Wallet Provider key this issuer is willing to trust is inherently deployment-specific, exactly like
     * the issuer signing {@link ECKey} above. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ClientAttestationTrustAnchor.class)
    public ClientAttestationValidator clientAttestationValidator(
            ClientAttestationTrustAnchor trustAnchor, DpopReplayStore clientAttestationPopReplayStore,
            Oid4vciIssuerProperties properties, ObjectProvider<AttestationChallengeService> attestationChallengeService) {
        return new ClientAttestationValidator(
                trustAnchor, clientAttestationPopReplayStore, Clock.systemUTC(), properties.getAttestationPopFreshness(),
                Optional.ofNullable(attestationChallengeService.getIfAvailable()));
    }

    /**
     * Static aside from the base URL (see {@link AuthorizationServerMetadataTemplate#resolve}), whether
     * {@code attest_jwt_client_auth} is supported, and whether {@code authorization_code} is supported:
     * this issuer signs DPoP proofs' counterpart tokens with ES256 throughout (see
     * {@link AccessTokenService}), so unlike {@link #credentialIssuerMetadataTemplate}, there's little
     * else here to bind from {@code oid4vci.issuer.*} properties. Gated on an {@link ECKey} bean like
     * {@link #tokenController}/{@link #jwksController}: this document only makes sense once those
     * endpoints actually exist to describe.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public AuthorizationServerMetadataTemplate authorizationServerMetadataTemplate(
            ObjectProvider<ClientAttestationTrustAnchor> clientAttestationTrustAnchor,
            ObjectProvider<AuthorizationClaimsResolver> authorizationClaimsResolver,
            Oid4vciIssuerProperties properties) {
        boolean attestationSupported = clientAttestationTrustAnchor.getIfAvailable() != null;
        boolean authorizationCodeSupported = authorizationClaimsResolver.getIfAvailable() != null;
        Optional<String> challengeEndpointPath = Optional.ofNullable(properties.getAttestationChallengeEndpointPath());

        List<String> authMethods = attestationSupported
                ? List.of("none", ClientAttestation.AUTH_METHOD)
                : List.of("none");
        List<String> attestationSigningAlgs = attestationSupported ? List.of("ES256") : List.of();

        List<String> grantTypes = new ArrayList<>();
        grantTypes.add("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        if (authorizationCodeSupported) {
            grantTypes.add("authorization_code");
        }

        return new AuthorizationServerMetadataTemplate(
                "/token", "/jwks",
                authorizationCodeSupported ? Optional.of("/authorize") : Optional.empty(),
                authorizationCodeSupported ? Optional.of("/par") : Optional.empty(),
                grantTypes,
                authorizationCodeSupported ? List.of("code") : List.of(),
                authorizationCodeSupported ? List.of("S256") : List.of(),
                authMethods,
                List.of("ES256"),
                List.of("openid_credential"),
                attestationSigningAlgs,
                attestationSigningAlgs,
                challengeEndpointPath);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public AuthorizationServerMetadataController authorizationServerMetadataController(
            AuthorizationServerMetadataTemplate template) {
        return new AuthorizationServerMetadataController(template);
    }

    private static JsonNode parseJson(String json, String propertyName) {
        if (json == null || json.isBlank()) {
            throw new IllegalStateException(propertyName + " is required");
        }
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("invalid " + propertyName + " JSON: " + json, e);
        }
    }
}
