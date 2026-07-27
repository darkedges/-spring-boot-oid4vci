package com.darkedges.oid4vci.spring.boot.autoconfigure;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataReader;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import com.darkedges.oid4vci.issuer.InMemoryCredentialOfferStore;
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
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.web.CredentialController;
import com.darkedges.oid4vci.issuer.web.CredentialOfferController;
import com.darkedges.oid4vci.issuer.web.IssuerMetadataController;
import com.darkedges.oid4vci.issuer.web.JwksController;
import com.darkedges.oid4vci.issuer.web.NonceController;
import com.darkedges.oid4vci.issuer.web.TokenController;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    public CredentialIssuerMetadata credentialIssuerMetadata(Oid4vciIssuerProperties properties) {
        String base = properties.getCredentialIssuer();
        ObjectNode root = MAPPER.createObjectNode();
        root.put("credential_issuer", base);
        root.put("credential_endpoint", base + properties.getCredentialEndpointPath());
        root.put("nonce_endpoint", base + properties.getNonceEndpointPath());
        JsonNode configurations = parseJson(properties.getCredentialConfigurationsSupported(),
                "oid4vci.issuer.credential-configurations-supported");
        root.set("credential_configurations_supported", configurations);
        return CredentialIssuerMetadataReader.read(root);
    }

    @Bean
    @ConditionalOnMissingBean
    public PreAuthorizedCodeStore preAuthorizedCodeStore() {
        return new InMemoryPreAuthorizedCodeStore();
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
    @ConditionalOnBean(ECKey.class)
    public AccessTokenService accessTokenService(ECKey issuerSigningKey, Oid4vciIssuerProperties properties) {
        return new AccessTokenService(issuerSigningKey, properties.getCredentialIssuer(), properties.getAccessTokenTtl(), Clock.systemUTC());
    }

    /**
     * {@code NimbusJwtDecoder.withJwkSetUri(...)} only trusts RS256 by default -- this issuer signs
     * access tokens with ES256 throughout (see {@link AccessTokenService}), so the algorithm must be
     * set explicitly or every token is rejected with "Another algorithm expected" regardless of the
     * JWKS content (confirmed live: this was missing on the first real end-to-end run against a live
     * demo issuer and every Credential Request failed with 401 until it was added).
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public JwtDecoder jwtDecoder(Oid4vciIssuerProperties properties) {
        return NimbusJwtDecoder.withJwkSetUri(properties.getCredentialIssuer() + "/jwks")
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
                issuerSigningKey, properties.getCredentialIssuer(), certificateChain,
                properties.getCredentialValidity(), Clock.systemUTC());
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

    @Bean
    @ConditionalOnMissingBean
    public IssuerMetadataController issuerMetadataController(CredentialIssuerMetadata metadata) {
        return new IssuerMetadataController(metadata);
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
            PreAuthorizedCodeService preAuthorizedCodeService, AccessTokenService accessTokenService, IssuedAccessTokenClaimsStore claimsStore) {
        return new TokenController(preAuthorizedCodeService, accessTokenService, claimsStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public CredentialController credentialController(
            CredentialIssuerMetadata metadata, ProofOfPossessionValidator proofValidator, IssuedAccessTokenClaimsStore claimsStore,
            Map<CredentialFormat, CredentialIssuanceService> issuanceServices) {
        return new CredentialController(metadata, proofValidator, claimsStore, issuanceServices);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ECKey.class)
    public JwksController jwksController(ECKey issuerSigningKey) {
        return new JwksController(issuerSigningKey);
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
