package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataWriter;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Serves the Credential Issuer Metadata document (OID4VCI 1.0, Section 12).
 *
 * <p>Returns a pre-serialized {@code String}, not {@code ObjectNode} directly: Spring Boot 4.1's default
 * {@code spring-boot-starter-web} now pulls in a Jackson 3 ({@code tools.jackson.*}) converter alongside
 * this project's Jackson 2 ({@code com.fasterxml.jackson.*}) one; the Jackson 3 converter doesn't
 * recognize a Jackson 2 {@code ObjectNode} as a tree node and falls back to bean-introspecting its
 * {@code isXxx()} predicate methods as if they were getters. Same workaround oid4vp's own
 * {@code AuthorizeController} already documents and uses.
 */
@RestController
public class IssuerMetadataController {

    private final CredentialIssuerMetadata metadata;

    public IssuerMetadataController(CredentialIssuerMetadata metadata) {
        this.metadata = metadata;
    }

    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> metadata() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)))
                .body(CredentialIssuerMetadataWriter.write(metadata).toString());
    }
}
