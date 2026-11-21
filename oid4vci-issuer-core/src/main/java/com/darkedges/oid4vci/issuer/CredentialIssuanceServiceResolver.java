package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

import java.util.Map;
import java.util.Optional;

/** Which service issues a credential of this format for this tenant. */
@FunctionalInterface
public interface CredentialIssuanceServiceResolver {

    Optional<CredentialIssuanceService> resolve(IssuerContext context, CredentialFormat format);

    /** The same services for every tenant, by format. */
    static CredentialIssuanceServiceResolver of(Map<CredentialFormat, CredentialIssuanceService> byFormat) {
        Map<CredentialFormat, CredentialIssuanceService> copy = Map.copyOf(byFormat);
        return (context, format) -> Optional.ofNullable(copy.get(format));
    }
}
