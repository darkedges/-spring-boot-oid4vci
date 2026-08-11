package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Serves the Authorization Server Metadata document (RFC 8414) at
 * {@code /.well-known/oauth-authorization-server} — the discovery path a Wallet (or the OpenID
 * Conformance Suite) falls back to when a Credential Issuer Metadata document has no
 * {@code authorization_servers} entry, meaning the Credential Issuer is its own Authorization Server (see
 * {@code CredentialIssuerMetadata}'s Javadoc). Built fresh on every request from
 * {@link RequestBaseUrl#resolve} — see {@link IssuerMetadataController}'s Javadoc for why.
 */
@RestController
public class AuthorizationServerMetadataController {

    private final AuthorizationServerMetadataTemplate template;

    public AuthorizationServerMetadataController(AuthorizationServerMetadataTemplate template) {
        this.template = template;
    }

    @GetMapping(value = "/.well-known/oauth-authorization-server", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> metadata(HttpServletRequest request) {
        String baseUrl = RequestBaseUrl.resolve(request);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)))
                .body(AuthorizationServerMetadataWriter.write(template.resolve(baseUrl)).toString());
    }
}
