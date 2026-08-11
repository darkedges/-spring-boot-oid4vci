package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.clientattestation.ClientAttestation;
import com.darkedges.oid4vci.core.dpop.DpopProof;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.token.AuthorizationCodeTokenRequest;
import com.darkedges.oid4vci.core.token.GrantType;
import com.darkedges.oid4vci.core.token.PreAuthorizedCodeTokenRequest;
import com.darkedges.oid4vci.core.token.TokenResponseWriter;
import com.darkedges.oid4vci.issuer.AccessTokenService;
import com.darkedges.oid4vci.issuer.AuthorizationCodeService;
import com.darkedges.oid4vci.issuer.ClientAttestationValidator;
import com.darkedges.oid4vci.issuer.DpopProofValidator;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

/**
 * The Token Endpoint (OID4VCI 1.0, Section 6) — {@code pre-authorized_code} always; {@code authorization_code}
 * too once the consuming app supplies an {@code AuthorizationClaimsResolver} bean (see
 * {@code AuthorizationEndpointController}, {@code Oid4vciIssuerAutoConfiguration}). After minting a
 * token, persists the redeemed session's claim values into {@link IssuedAccessTokenClaimsStore} keyed by
 * the token's subject, so {@link CredentialController} can look them up again later — see
 * {@link AccessTokenService#issue}'s Javadoc for why that hand-off exists. Returns a pre-serialized
 * {@code String} — see {@link IssuerMetadataController}'s Javadoc for why.
 *
 * <p>An optional {@code DPoP} request header (RFC 9449) sender-constrains the minted token to that
 * proof's key ({@code cnf.jkt}) — see {@link DpopProofValidator}. A client that never sends {@code DPoP}
 * gets a plain bearer token exactly as before; this is additive, not a breaking change to the existing
 * demo flow.
 *
 * <p>Optional {@code OAuth-Client-Attestation}/{@code OAuth-Client-Attestation-PoP} request headers
 * authenticate the client itself via {@code attest_jwt_client_auth} (see
 * {@link ClientAttestationValidator}) instead of the default {@code none} — only accepted when the
 * consuming app supplies a {@code ClientAttestationTrustAnchor} bean; both headers must be present
 * together or neither. The attested client id isn't otherwise used by this issuer (neither grant needs
 * one for anything functional) — successfully verifying it is the point, same as DPoP's
 * proof-of-possession check standing on its own.
 */
@RestController
public class TokenController {

    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final AccessTokenService accessTokenService;
    private final IssuedAccessTokenClaimsStore claimsStore;
    private final DpopProofValidator dpopProofValidator;
    private final Optional<ClientAttestationValidator> clientAttestationValidator;
    private final Optional<AuthorizationCodeService> authorizationCodeService;

    public TokenController(
            PreAuthorizedCodeService preAuthorizedCodeService, AccessTokenService accessTokenService,
            IssuedAccessTokenClaimsStore claimsStore, DpopProofValidator dpopProofValidator,
            Optional<ClientAttestationValidator> clientAttestationValidator,
            Optional<AuthorizationCodeService> authorizationCodeService) {
        this.preAuthorizedCodeService = preAuthorizedCodeService;
        this.accessTokenService = accessTokenService;
        this.claimsStore = claimsStore;
        this.dpopProofValidator = dpopProofValidator;
        this.clientAttestationValidator = clientAttestationValidator;
        this.authorizationCodeService = authorizationCodeService;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> token(
            @RequestParam Map<String, String> params,
            @RequestHeader(value = DpopProof.HEADER_NAME, required = false) String dpopProof,
            @RequestHeader(value = ClientAttestation.ATTESTATION_HEADER_NAME, required = false) String clientAttestation,
            @RequestHeader(value = ClientAttestation.ATTESTATION_POP_HEADER_NAME, required = false) String clientAttestationPop,
            HttpServletRequest servletRequest) {
        PreAuthorizedCodeSession session = redeem(params);

        String baseUrl = RequestBaseUrl.resolve(servletRequest);

        if (clientAttestation != null || clientAttestationPop != null) {
            if (clientAttestation == null || clientAttestationPop == null) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT,
                        ClientAttestation.ATTESTATION_HEADER_NAME + " and " + ClientAttestation.ATTESTATION_POP_HEADER_NAME
                                + " must both be present or both be absent");
            }
            if (clientAttestationValidator.isEmpty()) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_CLIENT, "attest_jwt_client_auth is not supported by this issuer");
            }
            clientAttestationValidator.get().verifyForTokenRequest(clientAttestation, clientAttestationPop, baseUrl);
        }

        Optional<String> dpopJkt = Optional.empty();
        if (dpopProof != null) {
            ECKey proofKey = dpopProofValidator.verifyForTokenRequest(dpopProof, HttpMethod.POST.name(), baseUrl + "/token");
            dpopJkt = Optional.of(DpopProofValidator.computeThumbprint(proofKey));
        }

        AccessTokenService.IssuedAccessToken issued = accessTokenService.issue(session, dpopJkt, baseUrl);
        claimsStore.save(issued.subject(), session.claims());

        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(TokenResponseWriter.write(issued.tokenResponse()).toString());
    }

    private PreAuthorizedCodeSession redeem(Map<String, String> params) {
        String grantType = params.get("grant_type");
        if (GrantType.PRE_AUTHORIZED_CODE.value().equals(grantType)) {
            return preAuthorizedCodeService.redeem(PreAuthorizedCodeTokenRequest.fromFormParams(params));
        }
        if (GrantType.AUTHORIZATION_CODE.value().equals(grantType) && authorizationCodeService.isPresent()) {
            return authorizationCodeService.get().redeem(AuthorizationCodeTokenRequest.fromFormParams(params));
        }
        throw new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_GRANT_TYPE, "unsupported or unknown grant_type: " + grantType);
    }
}
