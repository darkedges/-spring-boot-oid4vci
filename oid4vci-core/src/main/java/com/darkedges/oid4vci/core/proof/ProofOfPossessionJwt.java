package com.darkedges.oid4vci.core.proof;

/**
 * Constants for the {@code jwt} Proof Type's proof-of-possession JWT (OID4VCI 1.0, Appendix F.1 /
 * Section 8.2). Building and verifying the actual JWT lives in {@code oid4vci-wallet-core} and
 * {@code oid4vci-issuer-core} respectively (this module has no Nimbus/crypto dependency), matching how
 * {@code KbJwtBuilder}/{@code KbJwtVerifier} live in oid4vp's SD-JWT VC *format* module rather than
 * {@code oid4vp-core}.
 *
 * <p>{@link #TYP} was confirmed by decoding the base64url JWT header from the spec's own worked example
 * in Section 8.2 ({@code eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Ii...}), which decodes
 * to {@code {"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":{...}}} — not
 * {@code "application/openid4vci-proof+jwt"}, the media-type spelling used in prose elsewhere in the
 * spec (the {@code typ} JOSE header conventionally omits the {@code application/} prefix, per RFC 8725
 * §3.11 — the same convention {@code KbJwtBuilder} already follows for {@code dc+sd-jwt} elsewhere in
 * this project).
 */
public final class ProofOfPossessionJwt {

    /** The JWS header {@code typ} value for a {@code jwt}-type proof of possession. */
    public static final String TYP = "openid4vci-proof+jwt";

    private ProofOfPossessionJwt() {}
}
