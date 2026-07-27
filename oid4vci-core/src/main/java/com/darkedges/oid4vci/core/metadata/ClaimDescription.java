package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;

import java.util.Optional;

/**
 * One entry of a {@code credential_configurations_supported} entry's {@code claims} array (OID4VCI 1.0,
 * Appendix A). Reuses {@code oid4vp-core}'s {@link ClaimsPathPointer} directly for {@code path} — it's
 * the identical JSON-Pointer-like path shape DCQL already models, just describing a claim's location
 * within an issued credential rather than within a presentation query.
 *
 * @param path      REQUIRED — the claim's location within the credential.
 * @param mandatory OPTIONAL, defaults to {@code false} at the point of use if absent — whether the
 *                  Wallet is required to support this claim being present.
 */
public record ClaimDescription(ClaimsPathPointer path, Optional<Boolean> mandatory) {

    public ClaimDescription {
        if (path == null) {
            throw new IllegalArgumentException("path is required");
        }
        mandatory = mandatory == null ? Optional.empty() : mandatory;
    }
}
