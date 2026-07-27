package com.darkedges.oid4vci.core.credential;

/**
 * One element of a Credential Response's {@code credentials} array (OID4VCI 1.0, Section 8.3) — a small
 * wrapper object, not a bare string: {@code {"credential": "..."}}. Independently confirmed via search
 * (not paraphrased from memory) after this project's own domain model for
 * {@code proof_types_supported} was first written wrong as a plain array when it's actually an object —
 * treat every "is this a bare value or a wrapper object" question in this spec with real suspicion.
 *
 * @param credential the format's own raw wire encoding — an SD-JWT compact serialization, or a
 *                   base64url {@code IssuerSigned} CBOR structure for {@code mso_mdoc} — exactly the
 *                   input {@code SdJwtVcHeldCredential.parse}/{@code MdocHeldCredential.parse} expect.
 */
public record IssuedCredential(String credential) {

    public IssuedCredential {
        if (credential == null || credential.isBlank()) {
            throw new IllegalArgumentException("credential is required");
        }
    }
}
