package com.darkedges.oid4vci.wallet;

import java.net.URI;

/** Fetches a fresh {@code c_nonce} from a Nonce Endpoint. See {@link PreAuthorizedTokenEndpointClient}'s
 * Javadoc for why this stays crypto/HTTP-agnostic here. */
public interface NonceEndpointClient {

    String fetchNonce(URI nonceEndpoint);
}
