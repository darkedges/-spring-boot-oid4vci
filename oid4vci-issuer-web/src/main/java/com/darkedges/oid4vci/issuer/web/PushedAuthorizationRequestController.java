package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.authorize.AuthorizationRequest;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * The Pushed Authorization Request Endpoint (RFC 9126) — lets a client submit an Authorization Request
 * ahead of time and get back an opaque {@code request_uri} to present at {@code AuthorizationEndpointController}
 * instead of the request's parameters. Required by every {@code vci10issuer} OpenID Conformance Suite test
 * module unconditionally (see {@code AuthorizationServerMetadata}'s Javadoc) — this issuer still accepts
 * an inline Authorization Request too, so PAR is available but not mandatory.
 *
 * <p>Validates the pushed request eagerly with the same checks {@code AuthorizationEndpointController}'s
 * inline path applies, since RFC 9126 Section 2.3 expects malformed requests to be rejected here rather
 * than deferred to the eventual Authorization Endpoint call — unlike that controller, failures here are
 * always a direct JSON error response (never a redirect: {@code redirect_uri} hasn't been established
 * anywhere the client can be sent back to yet).
 */
@RestController
public class PushedAuthorizationRequestController {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration REQUEST_URI_TTL = Duration.ofSeconds(60);
    private static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

    private final PushedAuthorizationRequestStore store;

    public PushedAuthorizationRequestController(PushedAuthorizationRequestStore store) {
        this.store = store;
    }

    @PostMapping(value = "/par", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> pushAuthorizationRequest(@RequestParam Map<String, String> params) {
        URI redirectUri = parseRedirectUri(params.get("redirect_uri"));
        if (redirectUri == null) {
            return errorResponse("invalid_request", "redirect_uri is missing or is not a valid absolute URI");
        }

        AuthorizationRequest request;
        try {
            request = AuthorizationRequest.fromQueryParams(params, redirectUri, MAPPER);
        } catch (IllegalArgumentException e) {
            return errorResponse("invalid_request", e.getMessage());
        }

        Optional<AuthorizationRequestValidator.Error> error = AuthorizationRequestValidator.validate(request);
        if (error.isPresent()) {
            return errorResponse(error.get().error(), error.get().description());
        }

        String requestUri = REQUEST_URI_PREFIX + randomToken();
        store.save(requestUri, new PushedAuthorizationRequestEntry(request, Instant.now().plus(REQUEST_URI_TTL)));

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("request_uri", requestUri);
        body.put("expires_in", REQUEST_URI_TTL.toSeconds());
        return ResponseEntity.status(HttpStatus.CREATED).cacheControl(CacheControl.noStore()).body(body.toString());
    }

    private static ResponseEntity<String> errorResponse(String error, String description) {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("error", error);
        body.put("error_description", description);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).cacheControl(CacheControl.noStore()).body(body.toString());
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

    /** 256 bits of randomness, well above the suite's 96-bit minimum entropy requirement
     * ({@code EnsureMinimumRequestUriEntropy}, PAR-6.0). */
    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
