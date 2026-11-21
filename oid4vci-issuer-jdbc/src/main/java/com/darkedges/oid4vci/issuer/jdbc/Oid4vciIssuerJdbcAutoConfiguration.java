package com.darkedges.oid4vci.issuer.jdbc;

import com.darkedges.oid4vci.issuer.AuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import com.darkedges.oid4vci.issuer.DpopReplayStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.NonceStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;
import java.time.Clock;

/**
 * The issuer's stores in PostgreSQL ({@code oid4vci.issuer.store.type=jdbc}, the application's {@code DataSource}): shared by every
 * instance and kept across restarts. Registered before the issuer's auto-configuration, whose in-memory stores back off. The two
 * replay stores keep their bean names, so DPoP proofs and Client Attestation PoPs stay in separate jti namespaces.
 */
@AutoConfiguration(
        afterName = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
        beforeName = "com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerAutoConfiguration")
@ConditionalOnProperty(prefix = "oid4vci.issuer.store", name = "type", havingValue = "jdbc")
@EnableConfigurationProperties(IssuerStoreProperties.class)
public class Oid4vciIssuerJdbcAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public IssuerEntryTable issuerEntryTable(ObjectProvider<DataSource> dataSource, IssuerStoreProperties properties) {
        DataSource ds = dataSource.getIfAvailable();
        if (ds == null) throw new IllegalStateException("oid4vci.issuer.store.type=jdbc needs a DataSource (spring.datasource.*)");
        if (properties.isInitializeSchema()) {
            new ResourceDatabasePopulator(new ClassPathResource("oid4vci-issuer-jdbc/schema-postgresql.sql")).execute(ds);
        }
        return IssuerEntryTable.create(JdbcClient.create(ds), properties.getEncryptionKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public PreAuthorizedCodeStore preAuthorizedCodeStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.PreAuthorizedCodes(table);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationCodeStore authorizationCodeStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.AuthorizationCodes(table);
    }

    @Bean
    @ConditionalOnMissingBean
    public PushedAuthorizationRequestStore pushedAuthorizationRequestStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.PushedAuthorizationRequests(table);
    }

    @Bean
    @ConditionalOnMissingBean
    public NonceStore nonceStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.Nonces(table);
    }

    @Bean
    @ConditionalOnMissingBean
    public IssuedAccessTokenClaimsStore issuedAccessTokenClaimsStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.AccessTokenClaims(table);
    }

    @Bean
    @ConditionalOnMissingBean
    public CredentialOfferStore credentialOfferStore(IssuerEntryTable table, IssuerStoreProperties properties) {
        return new JdbcIssuerStores.CredentialOffers(table, properties.getOfferTtl(), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean(name = "dpopReplayStore")
    public DpopReplayStore dpopReplayStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.ReplayRecords(table, JdbcIssuerStores.DPOP_JTI);
    }

    @Bean
    @ConditionalOnMissingBean(name = "clientAttestationPopReplayStore")
    public DpopReplayStore clientAttestationPopReplayStore(IssuerEntryTable table) {
        return new JdbcIssuerStores.ReplayRecords(table, JdbcIssuerStores.ATTESTATION_POP_JTI);
    }
}
