package com.darkedges.oid4vci.wallet;

import com.nimbusds.jose.jwk.ECKey;

/**
 * Selects or generates the key the Wallet is about to bind into a credential being issued.
 *
 * <p>Deliberately <em>not</em> a reuse of {@code oid4vp-wallet-core}'s {@code HolderKeyResolver}: that
 * interface looks up the signer for an <em>already-issued</em> credential's existing confirmation key.
 * During issuance there is no credential yet — the Wallet must choose (or generate) the key about to be
 * bound, a different lifecycle with a different contract. {@link ECKey} already carries everything a
 * caller needs (a public JWK via {@code toPublicJWK()}, and — since a real key pair is expected here,
 * not a public-only one — a private key usable to build an {@code ECDSASigner}), so there's no need for
 * a bespoke wrapper type.
 */
public interface WalletBindingKeyResolver {

    ECKey resolve(String credentialConfigurationId);
}
