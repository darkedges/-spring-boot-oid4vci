package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.token.PreAuthorizedCodeTokenRequest;
import com.darkedges.oid4vci.core.token.TokenResponseWriter;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * The Token Endpoint (OID4VCI 1.0, Section 6) — pre-authorized_code grant only in v1. After minting a
 * token, persists the redeemed session's claim values into {@link IssuedAccessTokenClaimsStore} keyed by
 * the token's subject, so {@link CredentialController} can look them up again later — see
 * {@link AccessTokenService#issue}'s Javadoc for why that hand-off exists. Returns a pre-serialized
 * {@code String} — see {@link IssuerMetadataController}'s Javadoc for why.
 */
@RestController
public class TokenController {

    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final AccessTokenService accessTokenService;
    private final IssuedAccessTokenClaimsStore claimsStore;

    public TokenController(
            PreAuthorizedCodeService preAuthorizedCodeService, AccessTokenService accessTokenService,
            IssuedAccessTokenClaimsStore claimsStore) {
        this.preAuthorizedCodeService = preAuthorizedCodeService;
        this.accessTokenService = accessTokenService;
        this.claimsStore = claimsStore;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> token(@RequestParam Map<String, String> params) {
        PreAuthorizedCodeTokenRequest request = PreAuthorizedCodeTokenRequest.fromFormParams(params);
        PreAuthorizedCodeSession session = preAuthorizedCodeService.redeem(request);

        AccessTokenService.IssuedAccessToken issued = accessTokenService.issue(session);
        claimsStore.save(issued.subject(), session.claims());

        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(TokenResponseWriter.write(issued.tokenResponse()).toString());
    }
}
