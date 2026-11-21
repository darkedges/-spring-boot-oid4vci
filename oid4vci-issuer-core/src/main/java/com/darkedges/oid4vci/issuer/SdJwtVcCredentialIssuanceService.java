package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.sdjwt.Disclosure;
import com.fasterxml.jackson.databind.node.TextNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Builds an SD-JWT VC ({@code dc+sd-jwt}) credential. This is essentially
 * {@code DemoCredentialConfig.demoCredential()} (oid4vp-demo-wallet) promoted into a reusable,
 * parameterized service — issuer key, {@code vct}, claim map, and holder-binding key all become
 * per-call inputs instead of hardcoded constants — reusing {@link Disclosure#createObjectProperty}
 * directly from {@code oid4vp-format-sdjwt-vc}.
 */
public final class SdJwtVcCredentialIssuanceService implements CredentialIssuanceService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final IssuerKeys keys;
    /** A fixed chain for a single-tenant issuer; {@code null}: each tenant key's own {@code x5c}. */
    private final List<String> fixedCertificateChain;
    private final Duration validity;
    private final Clock clock;

    public SdJwtVcCredentialIssuanceService(
            ECKey issuerKey, List<String> certificateChain, Duration validity, Clock clock) {
        this.keys = IssuerKeys.fixed(issuerKey, null);
        this.fixedCertificateChain = certificateChain == null ? List.of() : List.copyOf(certificateChain);
        this.validity = validity;
        this.clock = clock;
    }

    /** Signs each tenant's credentials with that tenant's signing key, carrying the key's own certificate chain as {@code x5c}. */
    public SdJwtVcCredentialIssuanceService(IssuerKeys keys, Duration validity, Clock clock) {
        this.keys = keys;
        this.fixedCertificateChain = null;
        this.validity = validity;
        this.clock = clock;
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    @Override
    public String issue(CredentialConfiguration configuration, Map<String, String> claims, ECKey holderKey, String issuerBaseUrl) {
        return issue(IssuerContext.single(issuerBaseUrl), configuration, claims, holderKey);
    }

    @Override
    public String issue(IssuerContext context, CredentialConfiguration configuration, Map<String, String> claims, ECKey holderKey) {
        String issuerBaseUrl = context.issuerIdentifier();
        ECKey issuerKey = keys.signingKey(context);
        List<String> certificateChain = fixedCertificateChain != null ? fixedCertificateChain
                : issuerKey.getX509CertChain() == null ? List.of() : issuerKey.getX509CertChain().stream().map(Object::toString).toList();
        if (!(configuration instanceof SdJwtVcCredentialConfiguration sdJwtVcConfiguration)) {
            throw new IllegalArgumentException(
                    "expected an SdJwtVcCredentialConfiguration, got: " + configuration.getClass().getSimpleName());
        }

        List<Disclosure> disclosures = new ArrayList<>();
        List<String> digests = new ArrayList<>();
        for (Map.Entry<String, String> claim : claims.entrySet()) {
            Disclosure disclosure = Disclosure.createObjectProperty(
                    randomSalt(), claim.getKey(), TextNode.valueOf(claim.getValue()));
            disclosures.add(disclosure);
            digests.add(disclosure.digest());
        }

        Instant now = clock.instant();
        JWTClaimsSet issuerClaims = new JWTClaimsSet.Builder()
                .issuer(issuerBaseUrl)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(validity)))
                .claim("vct", sdJwtVcConfiguration.vct())
                .claim("_sd", digests)
                .claim("_sd_alg", "sha-256")
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                .build();

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(SdJwtVcCredentialConfiguration.WIRE_FORMAT))
                .keyID(issuerKey.getKeyID());
        if (!certificateChain.isEmpty()) {
            headerBuilder.x509CertChain(certificateChain.stream().map(com.nimbusds.jose.util.Base64::new).toList());
        }
        JWSHeader header = headerBuilder.build();
        SignedJWT issuerJwt = new SignedJWT(header, issuerClaims);
        try {
            issuerJwt.sign(new ECDSASigner(issuerKey));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to sign SD-JWT VC credential", e);
        }

        StringBuilder issuance = new StringBuilder(issuerJwt.serialize());
        for (Disclosure disclosure : disclosures) {
            issuance.append('~').append(disclosure.rawBase64Url());
        }
        issuance.append('~');
        return issuance.toString();
    }

    private static String randomSalt() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
