package com.darkedges.oid4vci.spring.boot.autoconfigure;

import java.security.PrivateKey;
import java.util.List;

/**
 * The issuer's mdoc ({@code IssuerAuth}) signing key material, bundled into one bean type so
 * {@link Oid4vciIssuerAutoConfiguration} has a single well-typed thing to inject rather than an
 * ambiguous bare {@code List<String>} bean for the certificate chain. Deliberately not auto-provided —
 * see the module Javadoc.
 */
public record MdocIssuerKeyMaterial(PrivateKey privateKey, List<String> certificateChain) {
}
