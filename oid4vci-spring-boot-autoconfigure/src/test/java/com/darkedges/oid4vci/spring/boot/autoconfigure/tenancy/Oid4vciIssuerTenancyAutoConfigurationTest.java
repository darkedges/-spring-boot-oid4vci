package com.darkedges.oid4vci.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.admin.TenantSettingsValidator;
import com.darkedges.oid4vc.tenancy.autoconfigure.TenancyAutoConfiguration;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.darkedges.oid4vci.issuer.IssuerMetadataTemplates;
import com.darkedges.oid4vci.issuer.web.CredentialController;
import com.darkedges.oid4vci.issuer.web.IssuerAccessTokenDecoder;
import com.darkedges.oid4vci.issuer.web.JwksController;
import com.darkedges.oid4vci.issuer.web.TokenController;
import com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerAutoConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vciIssuerTenancyAutoConfigurationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DEPLOYMENT_CONFIGURATIONS =
            "{\"EmployeeCredential\":{\"format\":\"dc+sd-jwt\",\"vct\":\"https://vct.example/employee\"}}";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TenancyAutoConfiguration.class,
                    Oid4vciIssuerTenancyAutoConfiguration.class, Oid4vciIssuerAutoConfiguration.class))
            .withPropertyValues(
                    "oid4vci.issuer.credential-configurations-supported=" + DEPLOYMENT_CONFIGURATIONS,
                    "oid4vc.tenancy.enabled=true",
                    "oid4vc.tenancy.store.type=memory",
                    "oid4vc.tenancy.platform-origins=https://issuer.zkp.au",
                    "oid4vc.tenancy.authstack.api-url=https://authstack.example");

    private static IssuerContext at(Tenant tenant) {
        return new IssuerContext(tenant.id(), "https://" + tenant.slug() + ".issuer.zkp.au");
    }

    @Test
    void withoutTenancyNothingChanges() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Oid4vciIssuerTenancyAutoConfiguration.class, Oid4vciIssuerAutoConfiguration.class))
                .withPropertyValues("oid4vci.issuer.credential-configurations-supported=" + DEPLOYMENT_CONFIGURATIONS)
                .withBean(com.nimbusds.jose.jwk.ECKey.class, () -> {
                    try { return new ECKeyGenerator(Curve.P_256).keyID("one").generate(); } catch (Exception e) { throw new IllegalStateException(e); }
                })
                .run(context -> {
                    assertThat(context).hasNotFailed().doesNotHaveBean(TenantIssuerKeys.class).hasSingleBean(TokenController.class);
                    IssuerKeys keys = context.getBean(IssuerKeys.class);
                    assertThat(keys.signingKey(IssuerContext.single("https://a")).getKeyID()).isEqualTo("one");
                });
    }

    @Test
    void theIssuerServesEveryTenantWithItsOwnKeysAndNoApplicationKey() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(IssuerKeys.class)).isInstanceOf(TenantIssuerKeys.class);
            assertThat(context).hasSingleBean(TokenController.class).hasSingleBean(CredentialController.class).hasSingleBean(JwksController.class);
            assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(IssuerAccessTokenDecoder.class);
            assertThat(context.getBean("mdocCredentialIssuanceService", CredentialIssuanceService.class)).isNotNull();

            TenantRepository tenants = context.getBean(TenantRepository.class);
            Tenant bank = tenants.save(Tenant.create("env-bank", "org-1", "bank"));
            Tenant shop = tenants.save(Tenant.create("env-shop", "org-2", "shop"));
            IssuerKeys keys = context.getBean(IssuerKeys.class);
            var bankKey = keys.signingKey(at(bank));
            assertThat(keys.signingKey(at(bank)).getKeyID()).isEqualTo(bankKey.getKeyID());
            assertThat(keys.signingKey(at(shop)).getKeyID()).isNotEqualTo(bankKey.getKeyID());
            assertThat(bankKey.getX509CertChain()).hasSize(1);
            assertThat(keys.mdocKey(at(bank))).isPresent();
            assertThat(keys.verificationKeys(at(bank))).extracting(k -> k.getKeyID()).containsExactly(bankKey.getKeyID());

            // The issuer comes from the tenancy filter's context, on the URL the tenant was reached on.
            var resolver = context.getBean(com.darkedges.oid4vci.issuer.web.IssuerContextResolver.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setAttribute(com.darkedges.oid4vc.tenancy.TenantContext.ATTRIBUTE, new com.darkedges.oid4vc.tenancy.TenantContext(
                    shop, com.darkedges.oid4vc.tenancy.TenantContext.Routing.PATH, "https", "issuer.zkp.au", "/t/shop"));
            assertThat(resolver.resolve(request)).isEqualTo(new IssuerContext("env-shop", "https://issuer.zkp.au/t/shop"));
        });
    }

    @Test
    void eachTenantPublishesItsOwnCredentialsAndTrust() {
        runner.run(context -> {
            TenantRepository tenants = context.getBean(TenantRepository.class);
            ObjectNode settings = (ObjectNode) MAPPER.readTree("""
                    {"credentialConfigurationsSupported":{"LoyaltyCard":{"format":"dc+sd-jwt","vct":"https://vct.example/loyalty"}},
                     "batchCredentialIssuanceMaxSize": 4,
                     "clientAttestation":{"trustedIssuer":"https://wallet-provider.example",
                                          "trustedIssuerKey":%s}}
                    """.formatted(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString()));
            Tenant shop = tenants.save(Tenant.create("env-shop", "org-2", "shop").withSettings(settings));
            Tenant bank = tenants.save(Tenant.create("env-bank", "org-1", "bank"));
            IssuerMetadataTemplates templates = context.getBean(IssuerMetadataTemplates.class);

            var shopMetadata = templates.credentialIssuer(at(shop)).resolve(at(shop).issuerIdentifier());
            assertThat(shopMetadata.credentialConfigurationsSupported()).containsOnlyKeys("LoyaltyCard");
            assertThat(shopMetadata.credentialIssuer().toString()).isEqualTo("https://shop.issuer.zkp.au");
            assertThat(shopMetadata.batchCredentialIssuance()).get().extracting(b -> b.batchSize()).isEqualTo(4);
            // A tenant with no credential settings offers the deployment's.
            assertThat(templates.credentialIssuer(at(bank)).resolve(at(bank).issuerIdentifier()).credentialConfigurationsSupported())
                    .containsOnlyKeys("EmployeeCredential");

            // Only the shop trusts a Wallet Provider, so only the shop advertises attest_jwt_client_auth.
            String shopAs = com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataWriter.write(
                    templates.authorizationServer(at(shop)).orElseThrow().resolve(at(shop).issuerIdentifier())).toString();
            String bankAs = com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataWriter.write(
                    templates.authorizationServer(at(bank)).orElseThrow().resolve(at(bank).issuerIdentifier())).toString();
            assertThat(shopAs).contains("attest_jwt_client_auth");
            assertThat(bankAs).doesNotContain("attest_jwt_client_auth");

            // A settings change shows at once.
            tenants.save(tenants.findById("env-shop").orElseThrow().withSettings(MAPPER.createObjectNode()));
            assertThat(templates.credentialIssuer(at(shop)).resolve(at(shop).issuerIdentifier()).credentialConfigurationsSupported())
                    .containsOnlyKeys("EmployeeCredential");
        });
    }

    @Test
    void theConsoleCannotSaveIssuerSettingsThatWouldNotWork() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(TenantSettingsValidator.class);
            TenantSettingsValidator validator = context.getBean(TenantSettingsValidator.class);
            assertThat(validator.validate((ObjectNode) MAPPER.readTree("{}"))).isEmpty();
            assertThat(validator.validate((ObjectNode) MAPPER.readTree("{\"batchCredentialIssuanceMaxSize\":0}"))).isNotEmpty();
            assertThat(validator.validate((ObjectNode) MAPPER.readTree("{\"credentialConfigurationsSupported\":{}}"))).isNotEmpty();
            assertThat(validator.validate((ObjectNode) MAPPER.readTree(
                    "{\"credentialConfigurationsSupported\":{\"X\":{\"format\":\"nonsense\"}}}"))).isNotEmpty();
            String privateKey = new ECKeyGenerator(Curve.P_256).generate().toJSONString();
            assertThat(validator.validate((ObjectNode) MAPPER.readTree(
                    "{\"clientAttestation\":{\"trustedIssuer\":\"https://w\",\"trustedIssuerKey\":" + privateKey + "}}")))
                    .anySatisfy(p -> assertThat(p).contains("public key only"));
        });
    }
}
