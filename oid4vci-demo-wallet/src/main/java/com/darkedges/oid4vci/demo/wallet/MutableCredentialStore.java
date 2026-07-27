package com.darkedges.oid4vci.demo.wallet;

import com.darkedges.oid4vci.wallet.HolderBoundCredential;
import com.darkedges.oid4vp.core.dcql.eval.CredentialStore;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.nimbusds.jose.jwk.ECKey;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A {@link CredentialStore} credentials can be added to after construction — {@code CredentialStore.of(...)}
 * (oid4vp-core's own factory) is immutable, fine for oid4vp-demo-wallet's startup-time self-issuance but
 * not for this app, which obtains credentials dynamically at runtime via HTTP.
 *
 * <p>Stores each {@link HeldCredential} paired with the {@link ECKey} it was bound to at issuance
 * ({@link HolderBoundCredential}), not just the bare credential — presenting a credential later (see
 * {@code WalletController}'s {@code /present} endpoint) needs that same private key back to sign a Key
 * Binding JWT or mdoc {@code DeviceAuth}; {@link #bindingKeyFor} looks it up by reference identity, since
 * {@link HeldCredential} implementations don't override {@code equals}/{@code hashCode} and a
 * {@code PresentationBuilder} always calls back with the exact instance {@link #findAll()} handed it.
 */
public final class MutableCredentialStore implements CredentialStore {

    private final AtomicReference<List<HolderBoundCredential>> credentials = new AtomicReference<>(List.of());

    @Override
    public List<HeldCredential> findAll() {
        return credentials.get().stream().map(HolderBoundCredential::credential).toList();
    }

    public Optional<ECKey> bindingKeyFor(HeldCredential credential) {
        return credentials.get().stream()
                .filter(c -> c.credential() == credential)
                .map(HolderBoundCredential::bindingKey)
                .findFirst();
    }

    public void addAll(List<HolderBoundCredential> newCredentials) {
        credentials.updateAndGet(existing -> {
            List<HolderBoundCredential> merged = new ArrayList<>(existing);
            merged.addAll(newCredentials);
            return List.copyOf(merged);
        });
    }
}
