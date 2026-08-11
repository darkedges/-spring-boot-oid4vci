package com.darkedges.oid4vci.spring.boot.autoconfigure;

import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.AuthorizationClaimsResolver;
import com.darkedges.oid4vci.issuer.AuthorizationCodeService;
import com.darkedges.oid4vci.issuer.ClientAttestationTrustAnchor;
import com.darkedges.oid4vci.issuer.ClientAttestationValidator;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import com.darkedges.oid4vci.issuer.NonceStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.web.AuthorizationEndpointController;
import com.darkedges.oid4vci.issuer.web.AuthorizationServerMetadataController;
import com.darkedges.oid4vci.issuer.web.CredentialController;
import com.darkedges.oid4vci.issuer.web.IssuerMetadataController;
import com.darkedges.oid4vci.issuer.web.JwksController;
import com.darkedges.oid4vci.issuer.web.NonceController;
import com.darkedges.oid4vci.issuer.web.Oid4vciExceptionHandler;
import com.darkedges.oid4vci.issuer.web.PushedAuthorizationRequestController;
import com.darkedges.oid4vci.issuer.web.TokenController;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

/** Exercises {@link Oid4vciIssuerAutoConfiguration} with a representative {@code oid4vci.issuer.*}
 * property set, using a Spring Boot {@link ApplicationContextRunner} rather than a full application. */
class Oid4vciIssuerAutoConfigurationTest {

    private static final String CREDENTIAL_CONFIGURATIONS = "{"
            + "\"UniversityDegreeCredential\":{\"format\":\"dc+sd-jwt\",\"vct\":\"https://issuer.example.org/vct/UniversityDegree\"}"
            + "}";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(Oid4vciIssuerAutoConfiguration.class))
            .withPropertyValues(
                    "oid4vci.issuer.credential-configurations-supported=" + CREDENTIAL_CONFIGURATIONS);

    @Test
    void wiresUpTheStoresAndMetadataEvenWithoutAnIssuerSigningKey() {
        contextRunner.run((AssertableApplicationContext context) -> {
            assertThat(context).hasSingleBean(PreAuthorizedCodeStore.class);
            assertThat(context).hasSingleBean(PushedAuthorizationRequestStore.class);
            assertThat(context).hasSingleBean(NonceStore.class);
            assertThat(context).hasSingleBean(CredentialOfferStore.class);
            assertThat(context).hasSingleBean(CredentialIssuerMetadataTemplate.class);
            assertThat(context).hasSingleBean(IssuerMetadataController.class);
            assertThat(context).hasSingleBean(NonceController.class);
            assertThat(context).hasSingleBean(Oid4vciExceptionHandler.class);

            CredentialIssuerMetadataTemplate template = context.getBean(CredentialIssuerMetadataTemplate.class);
            assertThat(template.resolve("https://issuer.example.org").credentialIssuer().toString())
                    .isEqualTo("https://issuer.example.org");
            assertThat(template.credentialConfigurationsSupported()).containsKey("UniversityDegreeCredential");

            // No ECKey bean supplied -- everything gated behind one must simply not be wired, not fail
            // the whole context (an app that only wants mdoc shouldn't need to fabricate an SD-JWT key).
            assertThat(context).doesNotHaveBean(AccessTokenService.class);
            assertThat(context).doesNotHaveBean(TokenController.class);
            assertThat(context).doesNotHaveBean(JwtDecoder.class);
            assertThat(context).doesNotHaveBean(JwksController.class);
            assertThat(context).doesNotHaveBean(AuthorizationServerMetadataController.class);
        });
    }

    @Test
    void wiresUpTheSigningDependentBeansOnceAnIssuerKeyIsSupplied() {
        contextRunner.withUserConfiguration(IssuerKeyConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(AccessTokenService.class);
            assertThat(context).hasSingleBean(TokenController.class);
            assertThat(context).hasSingleBean(JwtDecoder.class);
            assertThat(context).hasSingleBean(JwksController.class);
            assertThat(context).hasSingleBean(CredentialController.class);
            assertThat(context).hasSingleBean(AuthorizationServerMetadataController.class);
            assertThat(context).doesNotHaveBean(ClientAttestationValidator.class);
            // No AuthorizationClaimsResolver supplied -- the authorization_code grant, and everything that
            // advertises it, must stay entirely unwired (see AuthorizationClaimsResolver's Javadoc).
            assertThat(context).doesNotHaveBean(AuthorizationCodeService.class);
            assertThat(context).doesNotHaveBean(AuthorizationEndpointController.class);
            assertThat(context).doesNotHaveBean(PushedAuthorizationRequestController.class);
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).grantTypesSupported())
                    .containsExactly("urn:ietf:params:oauth:grant-type:pre-authorized_code");
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).authorizationEndpointPath())
                    .isEmpty();
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).pushedAuthorizationRequestEndpointPath())
                    .isEmpty();
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).tokenEndpointAuthMethodsSupported())
                    .containsExactly("none");
            assertThat(context).hasBean("sdJwtVcCredentialIssuanceService");
            assertThat(context.getBean("sdJwtVcCredentialIssuanceService", CredentialIssuanceService.class))
                    .isInstanceOf(SdJwtVcCredentialIssuanceService.class);

            @SuppressWarnings("unchecked")
            var issuanceServices = context.getBean(
                    "credentialIssuanceServices", java.util.Map.class);
            assertThat(issuanceServices).containsKey(CredentialFormat.DC_SD_JWT);
        });
    }

    @Test
    void advertisesAttestJwtClientAuthOnceATrustAnchorIsSupplied() {
        contextRunner.withUserConfiguration(IssuerKeyConfiguration.class, ClientAttestationTrustAnchorConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(ClientAttestationValidator.class);
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).tokenEndpointAuthMethodsSupported())
                    .contains("attest_jwt_client_auth");
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).clientAttestationSigningAlgValuesSupported())
                    .isNotEmpty();
            assertThat(context.getBean(AuthorizationServerMetadataTemplate.class).clientAttestationPopSigningAlgValuesSupported())
                    .isNotEmpty();
        });
    }

    @Test
    void wiresUpAClientAttestationTrustAnchorFromPlainPropertiesAloneNoBeanRequired() throws Exception {
        ECKey trustedKey = new ECKeyGenerator(Curve.P_256).algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .keyID("wallet-provider-1").generate();
        contextRunner.withUserConfiguration(IssuerKeyConfiguration.class)
                .withPropertyValues(
                        "oid4vci.issuer.client-attestation-trusted-issuer=https://wallet-provider.example.org",
                        "oid4vci.issuer.client-attestation-trusted-issuer-key=" + trustedKey.toPublicJWK().toJSONString())
                .run(context -> {
                    assertThat(context).hasSingleBean(ClientAttestationTrustAnchor.class);
                    assertThat(context).hasSingleBean(ClientAttestationValidator.class);
                    assertThat(context.getBean(ClientAttestationTrustAnchor.class).trustedIssuer())
                            .isEqualTo("https://wallet-provider.example.org");
                });
    }

    @Test
    void wiresUpTheAuthorizationCodeGrantOnceAClaimsResolverIsSupplied() {
        contextRunner.withUserConfiguration(IssuerKeyConfiguration.class, AuthorizationClaimsResolverConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(AuthorizationCodeService.class);
            assertThat(context).hasSingleBean(AuthorizationEndpointController.class);
            assertThat(context).hasSingleBean(PushedAuthorizationRequestController.class);

            AuthorizationServerMetadataTemplate template = context.getBean(AuthorizationServerMetadataTemplate.class);
            assertThat(template.grantTypesSupported())
                    .containsExactly("urn:ietf:params:oauth:grant-type:pre-authorized_code", "authorization_code");
            assertThat(template.authorizationEndpointPath()).contains("/authorize");
            assertThat(template.pushedAuthorizationRequestEndpointPath()).contains("/par");
            assertThat(template.responseTypesSupported()).containsExactly("code");
            assertThat(template.codeChallengeMethodsSupported()).containsExactly("S256");
        });
    }

    @Test
    void backsOffWhenUserSuppliesTheirOwnCredentialOfferStore() {
        contextRunner.withUserConfiguration(CustomCredentialOfferStoreConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(CredentialOfferStore.class);
            assertThat(context.getBean(CredentialOfferStore.class)).isSameAs(CustomCredentialOfferStoreConfiguration.INSTANCE);
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class IssuerKeyConfiguration {
        @Bean
        ECKey issuerSigningKey() throws Exception {
            return new ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ClientAttestationTrustAnchorConfiguration {
        @Bean
        ClientAttestationTrustAnchor clientAttestationTrustAnchor() throws Exception {
            return new ClientAttestationTrustAnchor(
                    "https://wallet-provider.example.org",
                    new ECKeyGenerator(Curve.P_256).keyID("wallet-provider-1").generate());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class AuthorizationClaimsResolverConfiguration {
        @Bean
        AuthorizationClaimsResolver authorizationClaimsResolver() {
            return credentialConfigurationIds -> java.util.Map.of("given_name", "Jane");
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomCredentialOfferStoreConfiguration {
        static final CredentialOfferStore INSTANCE = new com.darkedges.oid4vci.issuer.InMemoryCredentialOfferStore();

        @Bean
        CredentialOfferStore customOfferStore() {
            return INSTANCE;
        }
    }
}
