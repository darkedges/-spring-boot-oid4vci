package com.darkedges.oid4vci.issuer.jdbc;

import com.darkedges.oid4vci.issuer.DpopReplayStore;
import com.darkedges.oid4vci.issuer.NonceStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vciIssuerJdbcAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(Oid4vciIssuerJdbcAutoConfiguration.class))
            .withBean(DataSource.class, () -> new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/none"));

    @Test
    void offUnlessAskedFor() {
        runner.run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(IssuerEntryTable.class));
    }

    @Test
    void refusesToStoreIdentityClaimsWithoutAnEncryptionKey() {
        runner.withPropertyValues("oid4vci.issuer.store.type=jdbc", "oid4vci.issuer.store.initialize-schema=false")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("encryption-key is required"));
    }

    @Test
    void providesEveryStoreWithTheTwoReplayNamespacesApart() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        runner.withPropertyValues("oid4vci.issuer.store.type=jdbc", "oid4vci.issuer.store.initialize-schema=false",
                        "oid4vci.issuer.store.encryption-key=" + key)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(PreAuthorizedCodeStore.class)).isInstanceOf(JdbcIssuerStores.PreAuthorizedCodes.class);
                    assertThat(context.getBean(NonceStore.class)).isInstanceOf(JdbcIssuerStores.Nonces.class);
                    assertThat(context.getBeansOfType(DpopReplayStore.class)).containsOnlyKeys("dpopReplayStore", "clientAttestationPopReplayStore");
                });
    }

    @Test
    void theIssuersInMemoryStoresBackOff() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Oid4vciIssuerJdbcAutoConfiguration.class,
                        com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerAutoConfiguration.class))
                .withBean(DataSource.class, () -> new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/none"))
                .withBean(com.nimbusds.jose.jwk.ECKey.class, () -> {
                    try { return new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("k").generate(); }
                    catch (Exception e) { throw new IllegalStateException(e); }
                })
                .withPropertyValues("oid4vci.issuer.store.type=jdbc", "oid4vci.issuer.store.initialize-schema=false",
                        "oid4vci.issuer.store.encryption-key=" + key,
                        "oid4vci.issuer.credential-configurations-supported={\"C\":{\"format\":\"dc+sd-jwt\",\"vct\":\"https://vct.example/c\"}}")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(PreAuthorizedCodeStore.class)).isInstanceOf(JdbcIssuerStores.PreAuthorizedCodes.class);
                    assertThat(context.getBean(com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore.class))
                            .isInstanceOf(JdbcIssuerStores.AccessTokenClaims.class);
                    assertThat(context.getBeansOfType(DpopReplayStore.class).values())
                            .allSatisfy(store -> assertThat(store).isInstanceOf(JdbcIssuerStores.ReplayRecords.class)).hasSize(2);
                    assertThat(context).hasSingleBean(com.darkedges.oid4vci.issuer.web.TokenController.class);
                });
    }
}
