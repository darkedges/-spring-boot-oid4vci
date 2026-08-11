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
import java.util.Arrays;
import java.util.List;

/**
 * Loads the demo Issuer's signing key material from two checked-in PKCS12 keystores (one for SD-JWT
 * VC/access-token/JWKS signing, one for the mdoc {@code IssuerAuth} key) — same {@code keytool} technique
 * as {@code oid4vp-demo-wallet}'s {@code DemoMdocCredentialConfig} and {@code oid4vp-demo-verifier}'s
 * {@code DemoVerifierSigningKeyConfig}, except the leaf is CA-issued rather than self-signed: HAIP's
 * {@code ValidateSdJwtCredentialX5cCertificateChain} check (confirmed live against a real conformance
 * run) rejects a self-signed leaf outright, so {@code demo-issuer-signing-key.p12}'s {@code demo-issuer}
 * alias holds a 2-certificate chain — a leaf issued by (not the same cert as) a throwaway self-signed
 * "oid4vci Demo CA" root, both generated via plain {@code keytool -genkeypair}/{@code -certreq}/
 * {@code -gencert}, no real CA involved. {@code oid4vp-demo-verifier}'s own {@code IssuerKeyResolver}
 * still trusts the embedded chain's leaf outright with no path validation, so this is enough.
 *
 * <p>Only the non-self-signed entries of that chain go into the JWS {@code x5c} header ({@link #issuerSigningKey}):
 * the same HAIP check also rejects an x5c that includes the self-signed trust anchor itself (confirmed
 * live) — a verifier is expected to already trust that root out-of-band, not receive it inside the token —
 * so the root is filtered out, leaving just the leaf (or, with a deeper chain, leaf plus any intermediates).
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
        Certificate[] chain = keyStore.getCertificateChain(alias);
        ECPublicKey publicKey = (ECPublicKey) chain[0].getPublicKey();
        List<Base64> x5c = Arrays.stream(chain)
                .filter(cert -> !isSelfSigned(cert))
                .map(DemoIssuerKeyConfig::encode)
                .toList();

        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(alias)
                .x509CertChain(x5c)
                .build();
    }

    private static boolean isSelfSigned(Certificate certificate) {
        if (!(certificate instanceof java.security.cert.X509Certificate x509)) {
            return false;
        }
        return x509.getIssuerX500Principal().equals(x509.getSubjectX500Principal());
    }

    private static Base64 encode(Certificate certificate) {
        try {
            return Base64.encode(certificate.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException("failed to encode certificate from demo-issuer-signing-key.p12", e);
        }
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
