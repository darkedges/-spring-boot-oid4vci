package com.darkedges.oid4vci.core.token;

import java.util.Map;
import java.util.Optional;

/**
 * A Token Request using the pre-authorized_code grant (OID4VCI 1.0, Section 6.1) — transported as
 * {@code application/x-www-form-urlencoded}, not JSON, per OAuth 2.0 Token Endpoint convention, so this
 * type has a form-parameter factory rather than a JSON Reader.
 *
 * @param preAuthorizedCode REQUIRED.
 * @param txCode            OPTIONAL — required to be present iff the redeemed
 *                          {@code PreAuthorizedCodeGrant} carried a {@code tx_code} requirement (not
 *                          enforced by this type; the issuer-side service checks that).
 */
public record PreAuthorizedCodeTokenRequest(String preAuthorizedCode, Optional<String> txCode) {

    public PreAuthorizedCodeTokenRequest {
        if (preAuthorizedCode == null || preAuthorizedCode.isBlank()) {
            throw new IllegalArgumentException("pre-authorized_code is required");
        }
        txCode = txCode == null ? Optional.empty() : txCode;
    }

    /** Parses the request from its form-urlencoded fields (already decoded by the web layer), requiring
     * {@code grant_type} to be exactly {@link GrantType#PRE_AUTHORIZED_CODE}. */
    public static PreAuthorizedCodeTokenRequest fromFormParams(Map<String, String> params) {
        String grantType = params.get("grant_type");
        if (grantType == null || !GrantType.PRE_AUTHORIZED_CODE.value().equals(grantType)) {
            throw new IllegalArgumentException("grant_type must be " + GrantType.PRE_AUTHORIZED_CODE.value());
        }
        String preAuthorizedCode = params.get("pre-authorized_code");
        Optional<String> txCode = Optional.ofNullable(params.get("tx_code"));
        return new PreAuthorizedCodeTokenRequest(preAuthorizedCode, txCode);
    }
}
