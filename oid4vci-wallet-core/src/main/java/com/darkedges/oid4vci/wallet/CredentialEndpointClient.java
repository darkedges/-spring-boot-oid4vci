package com.darkedges.oid4vci.wallet;

import com.darkedges.oid4vci.core.credential.CredentialRequest;
import com.darkedges.oid4vci.core.credential.CredentialResponse;

import java.net.URI;

/** Sends a Credential Request to the Credential Endpoint with a bearer access token. See
 * {@link PreAuthorizedTokenEndpointClient}'s Javadoc for why this stays crypto/HTTP-agnostic here. */
public interface CredentialEndpointClient {

    CredentialResponse request(URI credentialEndpoint, String accessToken, CredentialRequest credentialRequest);
}
