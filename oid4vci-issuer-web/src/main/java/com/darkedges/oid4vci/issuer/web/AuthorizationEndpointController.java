package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.authorize.AuthorizationRequest;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.token.AuthorizationDetail;
import com.darkedges.oid4vci.issuer.AuthorizationClaimsResolver;
import com.darkedges.oid4vci.issuer.AuthorizationCodeEntry;
import com.darkedges.oid4vci.issuer.AuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Authorization Endpoint (RFC 6749 Section 3.1, as used by OID4VCI 1.0 Section 5) — {@code code}
 * response type only, PKCE (RFC 7636, S256) mandatory. Redirects straight back to {@code redirect_uri}
 * with a fresh code on every well-formed request: there's no login or consent screen anywhere in this
 * project (the Token/Nonce/Metadata/Offer endpoints already need none either — see the project README —
 * and an Authorization Endpoint choosing to auto-approve rather than prompt is exactly as spec-compliant;
 * OAuth never mandates that consent be interactive). Which claim values the resulting credential gets is
 * delegated to {@link AuthorizationClaimsResolver}, this endpoint's only substantive decision point — a
 * real issuer would replace that with an actual authenticated-user lookup.
 *
 * <p>Resolves which credential configuration(s) are being requested from {@code authorization_details}
 * (RFC 9396 RAR) if present, else from {@code scope} (matching each space-delimited scope-token against a
 * configuration's own {@code scope}, per HAIP Section 4.3's requirement that Wallets use {@code scope}
 * instead of RAR) if present, else falls back to every configuration this issuer supports.
 *
 * <p>Accepts a request two ways: every parameter inline as a query string (the {@link #authorizeInline}
 * path), or — RFC 9126 — a {@code request_uri} obtained from {@code PushedAuthorizationRequestController}
 * plus {@code client_id} (the {@link #authorizeWithPushedRequest} path). The latter is what every
 * {@code vci10issuer} OpenID Conformance Suite test module actually uses, unconditionally (confirmed
 * against {@code VCIProfileBehavior#initializeVariants}, which sets {@code isPar = true} regardless of
 * variant) — this issuer still accepts the inline form too, for Wallets that don't push.
 *
 * <p>Error handling follows RFC 6749 Section 4.1.2.1 for the inline path: an invalid or missing
 * {@code redirect_uri} is never redirected (the client can't be trusted to receive it) and gets a direct
 * {@code 400} instead; every other validation failure redirects back to {@code redirect_uri} with
 * {@code error}/{@code error_description} (and {@code state}, if the client sent one) query parameters.
 * The pushed-request path can't redirect at all on failure (an unknown/expired/mismatched
 * {@code request_uri} means {@code redirect_uri} was never actually established for this request) and
 * always responds directly instead.
 *
 * <p>Every redirect (success or error) carries an {@code iss} parameter identifying this issuer as the AS
 * that produced it (RFC 9207) — a Wallet juggling more than one AS uses it to tell which one a given
 * redirect actually came from, closing an authorization response mix-up attack.
 */
@RestController
public class AuthorizationEndpointController {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration CODE_TTL = Duration.ofMinutes(10);

    private final AuthorizationCodeStore codeStore;
    private final PushedAuthorizationRequestStore pushedRequestStore;
    private final CredentialIssuerMetadataTemplate template;
    private final AuthorizationClaimsResolver claimsResolver;

    public AuthorizationEndpointController(
            AuthorizationCodeStore codeStore, PushedAuthorizationRequestStore pushedRequestStore,
            CredentialIssuerMetadataTemplate template, AuthorizationClaimsResolver claimsResolver) {
        this.codeStore = codeStore;
        this.pushedRequestStore = pushedRequestStore;
        this.template = template;
        this.claimsResolver = claimsResolver;
    }

    @GetMapping("/authorize")
    public ResponseEntity<?> authorize(@RequestParam Map<String, String> params, HttpServletRequest servletRequest) {
        if (params.containsKey("request_uri")) {
            return authorizeWithPushedRequest(params, servletRequest);
        }
        return authorizeInline(params, servletRequest);
    }

    private ResponseEntity<?> authorizeInline(Map<String, String> params, HttpServletRequest servletRequest) {
        String issuer = RequestBaseUrl.resolve(servletRequest);
        URI redirectUri = parseRedirectUri(params.get("redirect_uri"));
        if (redirectUri == null) {
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN)
                    .body("redirect_uri is missing or is not a valid absolute URI");
        }

        AuthorizationRequest request;
        try {
            request = AuthorizationRequest.fromQueryParams(params, redirectUri, MAPPER);
        } catch (IllegalArgumentException e) {
            return redirectWithError(redirectUri, params.get("state"), "invalid_request", e.getMessage(), issuer);
        }

        Optional<AuthorizationRequestValidator.Error> error = AuthorizationRequestValidator.validate(request);
        if (error.isPresent()) {
            return redirectWithError(redirectUri, request.state().orElse(null), error.get().error(), error.get().description(), issuer);
        }

        return issueCodeAndRedirect(request, issuer);
    }

    private ResponseEntity<?> authorizeWithPushedRequest(Map<String, String> params, HttpServletRequest servletRequest) {
        String requestUri = params.get("request_uri");
        if (requestUri == null || requestUri.isBlank()) {
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("request_uri is missing");
        }

        PushedAuthorizationRequestEntry entry = pushedRequestStore.consume(requestUri).orElse(null);
        if (entry == null || entry.expiresAt().isBefore(Instant.now())) {
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN)
                    .body("request_uri is unknown, already used, or expired");
        }

        String clientId = params.get("client_id");
        if (clientId == null || !clientId.equals(entry.request().clientId())) {
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN)
                    .body("client_id does not match the pushed authorization request");
        }

        return issueCodeAndRedirect(entry.request(), RequestBaseUrl.resolve(servletRequest));
    }

    /** The tail both authorization flows share once a validated {@link AuthorizationRequest} is in hand:
     * resolve which credential configuration(s) it's for, mint a code, and redirect. */
    private ResponseEntity<?> issueCodeAndRedirect(AuthorizationRequest request, String issuer) {
        CredentialIssuerMetadata metadata = template.resolve(issuer);
        List<String> configurationIds;
        if (!request.authorizationDetails().isEmpty()) {
            configurationIds = request.authorizationDetails().stream()
                    .map(AuthorizationDetail::credentialConfigurationId).distinct().toList();
            for (String id : configurationIds) {
                if (!metadata.credentialConfigurationsSupported().containsKey(id)) {
                    return redirectWithError(request.redirectUri(), request.state().orElse(null),
                            "invalid_request", "unknown credential_configuration_id: " + id, issuer);
                }
            }
        } else if (!request.scopes().isEmpty()) {
            Map<String, String> configurationIdByScope = new HashMap<>();
            metadata.credentialConfigurationsSupported().forEach(
                    (id, configuration) -> configuration.scope().ifPresent(scope -> configurationIdByScope.put(scope, id)));

            List<String> resolved = new ArrayList<>();
            for (String scope : request.scopes()) {
                String id = configurationIdByScope.get(scope);
                if (id == null) {
                    return redirectWithError(request.redirectUri(), request.state().orElse(null),
                            "invalid_scope", "unknown scope: " + scope, issuer);
                }
                resolved.add(id);
            }
            configurationIds = resolved.stream().distinct().toList();
        } else {
            configurationIds = List.copyOf(metadata.credentialConfigurationsSupported().keySet());
        }

        String code = randomCode();
        codeStore.save(code, new AuthorizationCodeEntry(
                new PreAuthorizedCodeSession(
                        configurationIds, Optional.empty(), claimsResolver.resolveClaims(configurationIds),
                        Instant.now().plus(CODE_TTL)),
                request.redirectUri(), request.codeChallenge(), request.codeChallengeMethod()));

        return redirectWithCode(request.redirectUri(), request.state().orElse(null), code, issuer);
    }

    private static URI parseRedirectUri(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            URI uri = new URI(value);
            return uri.isAbsolute() ? uri : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static ResponseEntity<?> redirectWithCode(URI redirectUri, String state, String code, String issuer) {
        StringBuilder target = new StringBuilder(redirectUri.toString());
        appendQueryParam(target, "code", code);
        if (state != null) {
            appendQueryParam(target, "state", state);
        }
        appendQueryParam(target, "iss", issuer);
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(target.toString())).build();
    }

    private static ResponseEntity<?> redirectWithError(URI redirectUri, String state, String error, String description, String issuer) {
        StringBuilder target = new StringBuilder(redirectUri.toString());
        appendQueryParam(target, "error", error);
        if (description != null) {
            appendQueryParam(target, "error_description", description);
        }
        if (state != null) {
            appendQueryParam(target, "state", state);
        }
        appendQueryParam(target, "iss", issuer);
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(target.toString())).build();
    }

    /** Appends {@code &name=value} (or {@code ?name=value} for the first parameter), percent-encoding
     * {@code value} directly rather than round-tripping through {@code UriComponentsBuilder} — that type's
     * build-then-encode two-step risks double-encoding the redirect_uri's own already-encoded components. */
    private static void appendQueryParam(StringBuilder target, String name, String value) {
        boolean hasQueryAlready = target.indexOf("?") >= 0;
        target.append(hasQueryAlready ? '&' : '?')
                .append(name).append('=').append(URLEncoder.encode(value, StandardCharsets.UTF_8));
    }

    /** 256 bits of raw randomness — well above RFC 6749 Section 10.10's recommendation, and needed in
     * practice: the OpenID Conformance Suite's entropy check ({@code EnsureMinimumAuthorizationCodeEntropy},
     * RFC6749-10.10) computes Shannon entropy from the code's own character distribution rather than its
     * raw bit-length, and a short code has too few characters for that measurement to ever clear the
     * threshold even at full cryptographic randomness — confirmed live: 16 bytes (128 bits, 22 base64url
     * characters) failed this check; 32 bytes (the same length already used for {@code request_uri} in
     * {@code PushedAuthorizationRequestController}) passes comfortably. */
    private static String randomCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
