package com.darkedges.oid4vci.wallet;

import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.nimbusds.jose.jwk.ECKey;

/**
 * A {@link HeldCredential} paired with the {@link ECKey} (private key included) the Wallet bound into it
 * at issuance time, via {@link WalletBindingKeyResolver}. Without this pairing, a Wallet that stored only
 * the {@code HeldCredential} would have no way to later sign a presentation for it (an SD-JWT VC Key
 * Binding JWT, or an mdoc {@code DeviceAuth}) — the binding key would already be gone.
 */
public record HolderBoundCredential(HeldCredential credential, ECKey bindingKey) {
}
