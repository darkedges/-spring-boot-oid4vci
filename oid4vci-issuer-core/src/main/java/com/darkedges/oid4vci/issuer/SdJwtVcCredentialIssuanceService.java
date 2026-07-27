package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.sdjwt.Disclosure;
import com.fasterxml.jackson.databind.node.TextNode;
import com.nimbusds.jose.JOSEException;
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
 * Builds an SD-JWT VC ({@code vc+sd-jwt}) credential. This is essentially
 * {@code DemoCredentialConfig.demoCredential()} (oid4vp-demo-wallet) promoted into a reusable,
 * parameterized service — issuer key, {@code vct}, claim map, and holder-binding key all become
 * per-call inputs instead of hardcoded constants — reusing {@link Disclosure#createObjectProperty}
 * directly from {@code oid4vp-format-sdjwt-vc}.
 */
public final class SdJwtVcCredentialIssuanceService implements CredentialIssuanceService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ECKey issuerKey;
    private final String issuerUrl;
    private final List<String> certificateChain;
    private final Duration validity;
    private final Clock clock;

    public SdJwtVcCredentialIssuanceService(
            ECKey issuerKey, String issuerUrl, List<String> certificateChain, Duration validity, Clock clock) {
        this.issuerKey = issuerKey;
        this.issuerUrl = issuerUrl;
        this.certificateChain = certificateChain;
        this.validity = validity;
        this.clock = clock;
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    @Override
    public String issue(CredentialConfiguration configuration, Map<String, String> claims, ECKey holderKey) {
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
                .issuer(issuerUrl)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(validity)))
                .claim("vct", sdJwtVcConfiguration.vct())
                .claim("_sd", digests)
                .claim("_sd_alg", "sha-256")
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                .build();

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuerKey.getKeyID());
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
