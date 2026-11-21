package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.jdbc.IssuerEntryTable;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.util.Optional;

/**
 * Wiring for the identity-proofing flow.
 *
 * <p>The {@link Clock} is a bean rather than {@code Clock.systemUTC()} inline — which is what
 * {@code Oid4vciIssuerAutoConfiguration} does — because every expiry rule here (a session's TTL, a
 * pre-authorized code's, an MRZ two-digit year's century) is only testable against a clock that can
 * be moved.
 */
@Configuration
@EnableConfigurationProperties(ProofingProperties.class)
public class ProofingConfig {

    @Bean
    public Clock proofingClock() {
        return Clock.systemUTC();
    }

    /** In the issuer's PostgreSQL table when it has one (oid4vci.issuer.store.type=jdbc), in memory otherwise. */
    @Bean
    public ProofingSessionStore proofingSessionStore(ObjectProvider<IssuerEntryTable> table) {
        IssuerEntryTable shared = table.getIfAvailable();
        return shared != null ? new JdbcProofingSessionStore(shared) : new InMemoryProofingSessionStore();
    }

    /** Each tenant's {@code settings.proofing}; none for a single-tenant issuer. */
    @Bean
    public TenantProofingSettings tenantProofingSettings(ObjectProvider<TenantRepository> tenants) {
        return new TenantProofingSettings() {
            private Optional<JsonNode> settings(IssuerContext context) {
                TenantRepository repository = tenants.getIfAvailable();
                if (repository == null) return Optional.empty();
                return repository.findById(context.tenantId()).map(t -> t.settings().path("proofing")).filter(JsonNode::isObject);
            }

            @Override
            public boolean enabled(IssuerContext context) {
                return settings(context).map(p -> p.path("enabled").asBoolean(true)).orElse(true);
            }

            @Override
            public Optional<String> credentialConfigurationId(IssuerContext context) {
                return settings(context).map(p -> p.path("credentialConfigurationId").asText("")).filter(id -> !id.isBlank());
            }
        };
    }

    @Bean
    public PassportClaimsMapper passportClaimsMapper(Clock clock) {
        return new PassportClaimsMapper(clock);
    }
}
