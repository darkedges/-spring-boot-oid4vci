package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.nimbusds.jose.jwk.ECKey;

import java.util.Map;

/**
 * Builds one credential's raw wire encoding for a given format — the Issuer-side counterpart to
 * oid4vp's {@code PresentationVerifier}/{@code PresentationBuilder} interfaces, dispatched the same way
 * (one implementation per {@link CredentialFormat}, looked up by
 * {@code CredentialResponseFactory}/{@code oid4vci-issuer-web} in Phase 5).
 */
public interface CredentialIssuanceService {

    CredentialFormat format();

    /**
     * @param configuration the target {@code credential_configurations_supported} entry — must be the
     *                      implementation-specific subtype matching {@link #format()}.
     * @param claims        the claim values to embed, keyed by claim/element name (flat regardless of
     *                      format — see {@link PreAuthorizedCodeSession}).
     * @param holderKey     the Wallet's proof-of-possession public key, to bind into the credential.
     * @return the credential's raw wire encoding — exactly what
     *         {@code SdJwtVcHeldCredential.parse}/{@code MdocHeldCredential.parse} expect as input, and
     *         what a Credential Response's {@code credentials[].credential} field carries.
     */
    String issue(CredentialConfiguration configuration, Map<String, String> claims, ECKey holderKey);
}
