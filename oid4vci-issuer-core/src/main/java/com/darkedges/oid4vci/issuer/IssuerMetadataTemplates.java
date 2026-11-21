package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;

import java.util.Objects;
import java.util.Optional;

/**
 * What each tenant publishes: its Credential Issuer Metadata (which credentials it offers) and, if it is its own Authorization
 * Server, that metadata too. Resolved against the tenant's identifier per request.
 */
public interface IssuerMetadataTemplates {

    CredentialIssuerMetadataTemplate credentialIssuer(IssuerContext context);

    Optional<AuthorizationServerMetadataTemplate> authorizationServer(IssuerContext context);

    /** The same documents for every request: a single-tenant deployment. {@code authorizationServer} may be {@code null}. */
    static IssuerMetadataTemplates fixed(CredentialIssuerMetadataTemplate credentialIssuer,
                                         AuthorizationServerMetadataTemplate authorizationServer) {
        Objects.requireNonNull(credentialIssuer, "credentialIssuer");
        Optional<AuthorizationServerMetadataTemplate> as = Optional.ofNullable(authorizationServer);
        return new IssuerMetadataTemplates() {
            @Override
            public CredentialIssuerMetadataTemplate credentialIssuer(IssuerContext context) {
                return credentialIssuer;
            }

            @Override
            public Optional<AuthorizationServerMetadataTemplate> authorizationServer(IssuerContext context) {
                return as;
            }
        };
    }
}
