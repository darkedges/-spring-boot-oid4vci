package com.darkedges.oid4vci.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.TenantContext;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.admin.TenantSettingsValidator;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.issuer.AuthorizationClaimsResolver;
import com.darkedges.oid4vci.issuer.ClientAttestationTrustAnchor;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.darkedges.oid4vci.issuer.MsoMdocCredentialIssuanceService;
import com.darkedges.oid4vci.issuer.web.IssuerContextResolver;
import com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerAutoConfiguration;
import com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.util.Optional;

/**
 * Makes the issuer serve every tenant of an {@code oid4vc-tenancy} deployment ({@code oid4vc.tenancy.enabled=true}): each request's
 * issuer is its tenant on the URL it was reached on; each tenant signs with its own keys and publishes its own metadata; what one
 * tenant issued is unknown to every other.
 *
 * <p>Registered before {@link Oid4vciIssuerAutoConfiguration}, whose single-tenant beans back off, and before the tenancy
 * auto-configuration, so the console's admin API validates issuer settings with {@link TenantIssuerSettings#problems}.
 */
@AutoConfiguration(beforeName = {
        "com.darkedges.oid4vc.tenancy.autoconfigure.TenancyAutoConfiguration",
        "com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerAutoConfiguration"})
@ConditionalOnClass(TenantKeyService.class)
@ConditionalOnBooleanProperty(name = "oid4vc.tenancy.enabled")
@EnableConfigurationProperties(Oid4vciIssuerProperties.class)
public class Oid4vciIssuerTenancyAutoConfiguration {

    /** The request's tenant, on the URL it was reached on; 404 where no tenant is served. */
    @Bean
    @ConditionalOnMissingBean
    public IssuerContextResolver issuerContextResolver() {
        return request -> TenantContext.from(request)
                .map(tenant -> new IssuerContext(tenant.tenantId(), tenant.baseUrl()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no issuer is served here"));
    }

    @Bean
    @ConditionalOnMissingBean
    public IssuerKeys issuerKeys(TenantRepository tenants, TenantKeyService keys) {
        return new TenantIssuerKeys(tenants, keys);
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantIssuerSettings tenantIssuerSettings(
            TenantRepository tenants, Oid4vciIssuerProperties properties,
            ObjectProvider<CredentialIssuerMetadataTemplate> deploymentTemplate,
            ObjectProvider<ClientAttestationTrustAnchor> deploymentAnchor,
            ObjectProvider<AuthorizationClaimsResolver> claimsResolver) {
        return new TenantIssuerSettings(tenants, properties, deploymentTemplate::getObject,
                () -> Optional.ofNullable(deploymentAnchor.getIfAvailable()),
                () -> claimsResolver.getIfAvailable() != null);
    }

    /** Each tenant's mdocs, signed with its own mdoc key. */
    @Bean(name = "mdocCredentialIssuanceService")
    @ConditionalOnMissingBean(name = "mdocCredentialIssuanceService")
    public CredentialIssuanceService mdocCredentialIssuanceService(IssuerKeys issuerKeys, Oid4vciIssuerProperties properties) {
        return new MsoMdocCredentialIssuanceService(issuerKeys, properties.getCredentialValidity(), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantSettingsValidator tenantSettingsValidator(Oid4vciIssuerProperties properties) {
        return settings -> TenantIssuerSettings.problems(settings, properties);
    }
}
