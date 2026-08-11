package com.darkedges.oid4vci.issuer;

import java.util.List;
import java.util.Map;

/**
 * Resolves the claim values an {@code authorization_code} grant's eventual credential(s) should carry,
 * given the {@code credential_configuration_id}s the Authorization Request asked for (via
 * {@code authorization_details}, or every configuration this issuer supports if it sent none).
 *
 * <p>A stand-in for what would be a real user-authentication/consent step in a production issuer — this
 * project has no login of any kind (see {@code AuthorizationEndpointController}'s Javadoc for why an
 * immediate redirect is still spec-correct without one). No default implementation is auto-registered: a
 * consuming app that doesn't supply one simply doesn't get the {@code authorization_code} grant wired up
 * at all (see {@code Oid4vciIssuerAutoConfiguration}) — same "absence leaves that slice unwired" pattern
 * as {@link ClientAttestationTrustAnchor}.
 */
public interface AuthorizationClaimsResolver {

    Map<String, String> resolveClaims(List<String> credentialConfigurationIds);
}
