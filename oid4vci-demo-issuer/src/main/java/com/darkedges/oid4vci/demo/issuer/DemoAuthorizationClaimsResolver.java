package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.issuer.AuthorizationClaimsResolver;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Demo-only: hands back the same fixed claim values regardless of who's asking or which credential
 * configuration(s) were requested — standing in for a real authenticated-user/consent step, same spirit
 * as {@link DemoOfferController}'s hardcoded {@code given_name}/{@code family_name} for the
 * pre-authorized_code grant (matched here for consistency, not because the two grants need to agree on
 * anything). Not a pattern to copy for a real Issuer.
 */
@Component
public class DemoAuthorizationClaimsResolver implements AuthorizationClaimsResolver {

    @Override
    public Map<String, String> resolveClaims(List<String> credentialConfigurationIds) {
        return Map.of("given_name", "Jane", "family_name", "Doe");
    }
}
