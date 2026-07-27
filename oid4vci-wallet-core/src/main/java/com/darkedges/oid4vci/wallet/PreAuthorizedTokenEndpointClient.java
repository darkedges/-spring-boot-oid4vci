package com.darkedges.oid4vci.wallet;

import com.darkedges.oid4vci.core.token.TokenResponse;

import java.net.URI;
import java.util.Optional;

/**
 * Redeems a pre-authorized code at a Token Endpoint. Kept crypto/HTTP-agnostic exactly like
 * {@code oid4vp-core}'s {@code TokenEndpointClient}/{@code IssuerKeyResolver} — the real implementation
 * (a {@code RestClient} call) belongs at the application edge, i.e. {@code oid4vci-demo-wallet}, not a
 * dedicated autoconfigure module (this project has no wallet-side Spring integration at all — see the
 * README).
 */
public interface PreAuthorizedTokenEndpointClient {

    TokenResponse exchange(URI tokenEndpoint, String preAuthorizedCode, Optional<String> txCode);
}
