package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Serves the Credential Issuer Metadata document (OID4VCI 1.0, Section 12).
 *
 * <p>Built fresh on every request from {@link RequestBaseUrl#resolve} rather than once at startup from a
 * fixed config value — the same deployment can be reachable at more than one address (an internal Docker
 * network alias, a public reverse-proxy hostname, ...), and whichever one a client actually used is what
 * must come back as {@code credential_issuer} and the endpoint URLs, or a wallet/conformance-suite that
 * discovered this issuer at a public URL will be handed back internal addresses it can't reach.
 *
 * <p>Returns a pre-serialized {@code String}, not {@code ObjectNode} directly: Spring Boot 4.1's default
 * {@code spring-boot-starter-web} now pulls in a Jackson 3 ({@code tools.jackson.*}) converter alongside
 * this project's Jackson 2 ({@code com.fasterxml.jackson.*}) one; the Jackson 3 converter doesn't
 * recognize a Jackson 2 {@code ObjectNode} as a tree node and falls back to bean-introspecting its
 * {@code isXxx()} predicate methods as if they were getters. Same workaround oid4vp's own
 * {@code AuthorizeController} already documents and uses.
 *
 * <p>Deliberately has no {@code produces} restriction: this issuer doesn't implement signed metadata
 * (OID4VCI 1.0 Section 12.2's optional {@code application/jwt} representation), and the conformance
 * suite's signed-metadata test module sends {@code Accept: application/jwt} expecting to be handed back
 * the normal unsigned JSON anyway (it just checks the response {@code Content-Type} it actually got back
 * to decide whether to skip signature verification) -- confirmed against
 * {@code VCIIssuerMetadataSignedTest#checkIssuerMetadataResponse} in the conformance suite's own source.
 * Restricting {@code produces} to {@code application/json} made Spring MVC 406 that request instead.
 */
@RestController
public class IssuerMetadataController {

    private final CredentialIssuerMetadataTemplate template;

    public IssuerMetadataController(CredentialIssuerMetadataTemplate template) {
        this.template = template;
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    public ResponseEntity<String> metadata(HttpServletRequest request) {
        String baseUrl = RequestBaseUrl.resolve(request);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)))
                .body(CredentialIssuerMetadataWriter.write(template.resolve(baseUrl)).toString());
    }
}
