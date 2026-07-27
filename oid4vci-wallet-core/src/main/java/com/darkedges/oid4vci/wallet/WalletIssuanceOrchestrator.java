package com.darkedges.oid4vci.wallet;

import com.darkedges.oid4vci.core.credential.CredentialRequest;
import com.darkedges.oid4vci.core.credential.CredentialResponse;
import com.darkedges.oid4vci.core.credential.IssuedCredential;
import com.darkedges.oid4vci.core.credential.Proofs;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.Grants;
import com.darkedges.oid4vci.core.offer.PreAuthorizedCodeGrant;
import com.darkedges.oid4vci.core.token.AuthorizationDetail;
import com.darkedges.oid4vci.core.token.TokenResponse;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Drives the full pre-authorized_code issuance flow for a Credential Offer: token exchange, then per
 * offered configuration id, nonce fetch -&gt; proof build -&gt; credential request -&gt; dispatch each
 * returned raw credential into an {@code oid4vp-core} {@link HeldCredential} by format — the
 * {@code WalletAuthorizationResponseBuilder} analog for issuance rather than presentation.
 *
 * <p><strong>Known v1 simplification:</strong> the Token Endpoint URI is a caller-supplied parameter
 * rather than discovered via RFC 8414 Authorization Server Metadata at the Credential Issuer's own
 * origin (the correct discovery path when {@link CredentialIssuerMetadata#authorizationServers()} is
 * empty, i.e. the issuer is its own Authorization Server — the only case v1 supports). Full AS-metadata
 * discovery is deferred to a later phase; {@code oid4vci-demo-wallet} knows its issuer's token endpoint
 * out of band for now, the same kind of shortcut oid4vp's own demo apps take in several places.
 */
public final class WalletIssuanceOrchestrator {

    private final PreAuthorizedTokenEndpointClient tokenClient;
    private final NonceEndpointClient nonceClient;
    private final CredentialEndpointClient credentialClient;
    private final WalletBindingKeyResolver keyResolver;
    private final Clock clock;

    public WalletIssuanceOrchestrator(
            PreAuthorizedTokenEndpointClient tokenClient, NonceEndpointClient nonceClient,
            CredentialEndpointClient credentialClient, WalletBindingKeyResolver keyResolver, Clock clock) {
        this.tokenClient = tokenClient;
        this.nonceClient = nonceClient;
        this.credentialClient = credentialClient;
        this.keyResolver = keyResolver;
        this.clock = clock;
    }

    public List<HolderBoundCredential> obtainCredentials(
            CredentialOffer offer, CredentialIssuerMetadata metadata, URI tokenEndpoint, Supplier<Optional<String>> txCodeSupplier) {
        PreAuthorizedCodeGrant grant = offer.grants()
                .flatMap(Grants::preAuthorizedCode)
                .orElseThrow(() -> new IllegalArgumentException("Credential Offer has no pre-authorized_code grant"));

        Optional<String> txCode = grant.txCode().isPresent() ? txCodeSupplier.get() : Optional.empty();
        TokenResponse token = tokenClient.exchange(tokenEndpoint, grant.preAuthorizedCode(), txCode);

        URI nonceEndpoint = metadata.nonceEndpoint()
                .orElseThrow(() -> new IllegalStateException("Credential Issuer has no nonce_endpoint"));

        List<HolderBoundCredential> credentials = new ArrayList<>();
        for (String configurationId : offer.credentialConfigurationIds()) {
            CredentialConfiguration configuration = metadata.credentialConfigurationsSupported().get(configurationId);
            if (configuration == null) {
                throw new IllegalArgumentException(
                        "offer references a credential_configuration_id the issuer doesn't advertise: " + configurationId);
            }

            ECKey holderKey = keyResolver.resolve(configurationId);
            String nonce = nonceClient.fetchNonce(nonceEndpoint);
            SignedJWT proofJwt = ProofJwtBuilder.build(metadata.credentialIssuer().toString(), nonce, clock.instant(), holderKey);
            Proofs proofs = new Proofs(Optional.of(List.of(proofJwt.serialize())));

            CredentialRequest request = buildRequest(configurationId, token, proofs);
            CredentialResponse response = credentialClient.request(metadata.credentialEndpoint(), token.accessToken(), request);

            List<IssuedCredential> issued = response.credentials()
                    .orElseThrow(() -> new IllegalStateException("deferred issuance (transaction_id) is not supported in v1"));
            for (IssuedCredential credential : issued) {
                credentials.add(new HolderBoundCredential(parse(configuration.format(), credential.credential()), holderKey));
            }
        }
        return credentials;
    }

    private static CredentialRequest buildRequest(String configurationId, TokenResponse token, Proofs proofs) {
        Optional<String> credentialIdentifier = findCredentialIdentifier(configurationId, token);
        if (credentialIdentifier.isPresent()) {
            return new CredentialRequest(Optional.empty(), credentialIdentifier, Optional.of(proofs));
        }
        return new CredentialRequest(Optional.of(configurationId), Optional.empty(), Optional.of(proofs));
    }

    private static Optional<String> findCredentialIdentifier(String configurationId, TokenResponse token) {
        return token.authorizationDetails().flatMap(details -> details.stream()
                .filter(detail -> detail.credentialConfigurationId().equals(configurationId))
                .findFirst()
                .flatMap(AuthorizationDetail::credentialIdentifiers)
                .flatMap(ids -> ids.stream().findFirst()));
    }

    private static HeldCredential parse(CredentialFormat format, String rawCredential) {
        return switch (format) {
            case DC_SD_JWT -> SdJwtVcHeldCredential.parse(rawCredential);
            case MSO_MDOC -> MdocHeldCredential.parse(Base64.getUrlDecoder().decode(rawCredential));
            case JWT_VC_JSON, LDP_VC -> throw new IllegalArgumentException(
                    "no HeldCredential parser registered for format: " + format);
        };
    }
}
