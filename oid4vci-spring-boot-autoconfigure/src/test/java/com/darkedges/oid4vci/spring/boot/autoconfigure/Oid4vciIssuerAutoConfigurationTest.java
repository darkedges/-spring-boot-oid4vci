package com.darkedges.oid4vci.spring.boot.autoconfigure;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import com.darkedges.oid4vci.issuer.NonceStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.web.CredentialController;
import com.darkedges.oid4vci.issuer.web.IssuerMetadataController;
import com.darkedges.oid4vci.issuer.web.JwksController;
import com.darkedges.oid4vci.issuer.web.NonceController;
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
            + "\"UniversityDegreeCredential\":{\"format\":\"vc+sd-jwt\",\"vct\":\"https://issuer.example.org/vct/UniversityDegree\"}"
            + "}";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(Oid4vciIssuerAutoConfiguration.class))
            .withPropertyValues(
                    "oid4vci.issuer.credential-issuer=https://issuer.example.org",
                    "oid4vci.issuer.credential-configurations-supported=" + CREDENTIAL_CONFIGURATIONS);

    @Test
    void wiresUpTheStoresAndMetadataEvenWithoutAnIssuerSigningKey() {
        contextRunner.run((AssertableApplicationContext context) -> {
            assertThat(context).hasSingleBean(PreAuthorizedCodeStore.class);
            assertThat(context).hasSingleBean(NonceStore.class);
            assertThat(context).hasSingleBean(CredentialOfferStore.class);
            assertThat(context).hasSingleBean(CredentialIssuerMetadata.class);
            assertThat(context).hasSingleBean(IssuerMetadataController.class);
            assertThat(context).hasSingleBean(NonceController.class);

            CredentialIssuerMetadata metadata = context.getBean(CredentialIssuerMetadata.class);
            assertThat(metadata.credentialIssuer().toString()).isEqualTo("https://issuer.example.org");
            assertThat(metadata.credentialConfigurationsSupported()).containsKey("UniversityDegreeCredential");

            // No ECKey bean supplied -- everything gated behind one must simply not be wired, not fail
            // the whole context (an app that only wants mdoc shouldn't need to fabricate an SD-JWT key).
            assertThat(context).doesNotHaveBean(AccessTokenService.class);
            assertThat(context).doesNotHaveBean(TokenController.class);
            assertThat(context).doesNotHaveBean(JwtDecoder.class);
            assertThat(context).doesNotHaveBean(JwksController.class);
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
    static class CustomCredentialOfferStoreConfiguration {
        static final CredentialOfferStore INSTANCE = new com.darkedges.oid4vci.issuer.InMemoryCredentialOfferStore();

        @Bean
        CredentialOfferStore customOfferStore() {
            return INSTANCE;
        }
    }
}
