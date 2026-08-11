package com.darkedges.oid4vci.core.dpop;

/** Constants for a DPoP proof JWT (RFC 9449 Section 4.2). Kept alongside {@code ProofOfPossessionJwt} in
 * this module for the same reason: the constant itself has no Nimbus/crypto dependency, only the
 * validator/builder that uses it does. */
public final class DpopProof {

    /** The JWS header {@code typ} value for a DPoP proof JWT. */
    public static final String TYP = "dpop+jwt";

    /** The custom HTTP request header a DPoP proof JWT is carried in. */
    public static final String HEADER_NAME = "DPoP";

    private DpopProof() {}
}
