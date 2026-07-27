package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.metadata.ClaimDescription;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.MsoMdocCredentialConfiguration;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.PathComponent;
import com.darkedges.oid4vp.mdoc.MdocIssuer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;

import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an {@code mso_mdoc} credential by calling {@link MdocIssuer#issueIssuerSigned} directly — that
 * method already does essentially the whole job (builds {@code IssuerSignedItem}s, the MSO, and signs
 * {@code IssuerAuth}); the only net-new work here is grouping the session's flat claim map into mdoc
 * namespaces using the target configuration's own declared claim paths, and base64url-encoding the
 * resulting CBOR bytes for the JSON wire (OID4VCI 1.0: "binary data being base64url-encoded and returned
 * as a string" — {@code MdocHeldCredential.parse} takes raw bytes, so the Wallet side must decode this
 * back before calling it).
 */
public final class MsoMdocCredentialIssuanceService implements CredentialIssuanceService {

    /** Namespace used when a configuration declares no {@code claims} array at all — matches
     * {@code DemoMdocCredentialConfig}'s own self-issuance convention in oid4vp-demo-wallet. */
    private static final String DEFAULT_NAMESPACE = "org.iso.18013.5.1";

    private final PrivateKey issuerPrivateKey;
    private final List<String> issuerCertificateChain;
    private final Duration validity;
    private final Clock clock;

    public MsoMdocCredentialIssuanceService(
            PrivateKey issuerPrivateKey, List<String> issuerCertificateChain, Duration validity, Clock clock) {
        this.issuerPrivateKey = issuerPrivateKey;
        this.issuerCertificateChain = issuerCertificateChain;
        this.validity = validity;
        this.clock = clock;
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.MSO_MDOC;
    }

    @Override
    public String issue(CredentialConfiguration configuration, Map<String, String> claims, ECKey holderKey) {
        if (!(configuration instanceof MsoMdocCredentialConfiguration mdocConfiguration)) {
            throw new IllegalArgumentException(
                    "expected an MsoMdocCredentialConfiguration, got: " + configuration.getClass().getSimpleName());
        }

        ECPublicKey devicePublicKey;
        try {
            devicePublicKey = (ECPublicKey) holderKey.toECPublicKey();
        } catch (JOSEException e) {
            throw new IllegalArgumentException("holder key is not usable as an EC public key", e);
        }

        Map<String, Map<String, String>> claimsByNamespace = groupByNamespace(mdocConfiguration, claims);
        Instant now = clock.instant();

        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerPrivateKey, issuerCertificateChain, devicePublicKey, mdocConfiguration.doctype(),
                claimsByNamespace, now, now.plus(validity));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned);
    }

    private static Map<String, Map<String, String>> groupByNamespace(
            MsoMdocCredentialConfiguration configuration, Map<String, String> claims) {
        if (configuration.claims().isEmpty()) {
            Map<String, Map<String, String>> byNamespace = new LinkedHashMap<>();
            byNamespace.put(DEFAULT_NAMESPACE, new LinkedHashMap<>(claims));
            return byNamespace;
        }

        Map<String, Map<String, String>> byNamespace = new LinkedHashMap<>();
        for (ClaimDescription claim : configuration.claims()) {
            if (!claim.path().isMdocShape()) {
                throw new IllegalArgumentException(
                        "mso_mdoc claim description path must be exactly [namespace, element]: " + claim.path());
            }
            String namespace = ((PathComponent.Key) claim.path().components().get(0)).name();
            String element = ((PathComponent.Key) claim.path().components().get(1)).name();

            String value = claims.get(element);
            if (value == null) {
                if (claim.mandatory().orElse(false)) {
                    throw new IllegalArgumentException("mandatory claim \"" + element + "\" missing from session claims");
                }
                continue;
            }
            byNamespace.computeIfAbsent(namespace, ignored -> new LinkedHashMap<>()).put(element, value);
        }
        return byNamespace;
    }
}
