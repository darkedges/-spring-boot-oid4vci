package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.spring.boot.autoconfigure.MdocIssuerKeyMaterial;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

/**
 * Loads the demo Issuer's signing key material from two checked-in self-signed PKCS12 keystores
 * (one for SD-JWT VC/access-token/JWKS signing, one for the mdoc {@code IssuerAuth} key) — same
 * convention as {@code oid4vp-demo-wallet}'s {@code DemoMdocCredentialConfig} and
 * {@code oid4vp-demo-verifier}'s {@code DemoVerifierSigningKeyConfig}: generated once via
 * {@code keytool -genkeypair} (self-signed, no CA — {@code oid4vp-demo-verifier}'s own
 * {@code IssuerKeyResolver} trusts a credential's embedded {@code x5c}/{@code x5chain} leaf outright,
 * with no chain-of-trust validation, so a throwaway self-signed cert is enough).
 *
 * <p>Built via plain {@link KeyStore} rather than Nimbus's {@code ECKey.load(KeyStore, ...)}: that
 * convenience method reaches for BouncyCastle internally, and this project has no BouncyCastle
 * dependency — same reasoning as {@code DemoVerifierSigningKeyConfig}.
 *
 * <p>Embedding a real cert chain (rather than the previous fresh-every-startup, chain-less keys) is
 * what lets {@code oid4vp-demo-verifier} resolve this issuer's key straight from a presented
 * credential, closing the cross-repo interop gap documented in the project README.
 */
@Configuration
public class DemoIssuerKeyConfig {

    private static final char[] PASSWORD = "changeit".toCharArray();

    @Bean
    public ECKey issuerSigningKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = DemoIssuerKeyConfig.class.getResourceAsStream("/demo-issuer-signing-key.p12")) {
            keyStore.load(in, PASSWORD);
        }
        String alias = "demo-issuer";
        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(alias, PASSWORD);
        Certificate leaf = keyStore.getCertificateChain(alias)[0];
        ECPublicKey publicKey = (ECPublicKey) leaf.getPublicKey();
        List<Base64> x5c = List.of(Base64.encode(leaf.getEncoded()));

        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(alias)
                .x509CertChain(x5c)
                .build();
    }

    @Bean
    public MdocIssuerKeyMaterial mdocIssuerKeyMaterial() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = DemoIssuerKeyConfig.class.getResourceAsStream("/demo-issuer-mdoc-key.p12")) {
            keyStore.load(in, PASSWORD);
        }
        String alias = "demo-issuer-mdoc";
        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(alias, PASSWORD);
        Certificate leaf = keyStore.getCertificateChain(alias)[0];
        List<String> x5chain = List.of(java.util.Base64.getEncoder().encodeToString(leaf.getEncoded()));

        return new MdocIssuerKeyMaterial(privateKey, x5chain);
    }
}
