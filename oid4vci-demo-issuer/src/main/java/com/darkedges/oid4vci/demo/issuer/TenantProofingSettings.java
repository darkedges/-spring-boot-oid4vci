package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.issuer.IssuerContext;

import java.util.Optional;

/**
 * Each tenant's passport-proofing settings, from its {@code settings.proofing} (edited from the AuthStack console):
 * <pre>
 * "proofing": { "enabled": true, "credentialConfigurationId": "PassportCredential" }
 * </pre>
 * {@code enabled} defaults to true and {@code credentialConfigurationId} to {@code demo.proofing.credential-configuration-id}. The
 * proofing service's callback secret is the platform's, not a tenant's: one service calls one endpoint for every tenant.
 */
public interface TenantProofingSettings {

    boolean enabled(IssuerContext context);

    Optional<String> credentialConfigurationId(IssuerContext context);

    /** A single-tenant issuer: proofing on, with the deployment's configuration. */
    TenantProofingSettings NONE = new TenantProofingSettings() {
        @Override
        public boolean enabled(IssuerContext context) {
            return true;
        }

        @Override
        public Optional<String> credentialConfigurationId(IssuerContext context) {
            return Optional.empty();
        }
    };
}
