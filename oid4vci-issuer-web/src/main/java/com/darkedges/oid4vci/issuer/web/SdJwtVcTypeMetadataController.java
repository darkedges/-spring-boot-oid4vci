package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Serves SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc Section 6) for every {@code dc+sd-jwt}
 * {@code credential_configurations_supported} entry whose {@code vct} is issuer-relative (see
 * {@link SdJwtVcCredentialConfiguration#resolvedVct}) — a real HTTP GET straight to the {@code vct} URI
 * is exactly how a Verifier resolves Type Metadata per that spec (no {@code .well-known} indirection,
 * unlike Issuer Metadata), so this must exist and actually answer at that URL, or every issued
 * credential's {@code vct} is unresolvable. Only {@code vct} is echoed back — the one field the spec
 * requires — since this project's {@link CredentialConfiguration} model has no {@code name}/
 * {@code description}/{@code display} data to offer beyond that yet.
 *
 * <p>Mapped by {@code credential_configuration_id} (the path segment after {@code /vct/}), not by
 * parsing the configured {@code vct} path itself — simpler, and this project's demo config already
 * reuses the configuration id as its {@code scope} for the same reason (see {@code application.yml}).
 */
@RestController
public class SdJwtVcTypeMetadataController {

    private final CredentialIssuerMetadataTemplate template;

    public SdJwtVcTypeMetadataController(CredentialIssuerMetadataTemplate template) {
        this.template = template;
    }

    @GetMapping(value = "/vct/{credentialConfigurationId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> typeMetadata(
            @PathVariable String credentialConfigurationId, HttpServletRequest request) {
        String baseUrl = RequestBaseUrl.resolve(request);
        CredentialConfiguration configuration = template.resolve(baseUrl)
                .credentialConfigurationsSupported().get(credentialConfigurationId);
        if (!(configuration instanceof SdJwtVcCredentialConfiguration sdJwt)) {
            return ResponseEntity.notFound().build();
        }
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("vct", sdJwt.vct());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)))
                .body(body.toString());
    }
}
