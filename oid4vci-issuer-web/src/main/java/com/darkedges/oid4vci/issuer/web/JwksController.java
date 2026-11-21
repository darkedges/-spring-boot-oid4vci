package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Serves the Issuer's access-token-signing public key as a JWK Set — what a Spring
 * {@code NimbusJwtDecoder.withJwkSetUri(...)} (configured by {@code oid4vci-spring-boot-autoconfigure})
 * fetches to verify tokens presented at the Credential Endpoint. Routing verification through a real
 * JWKS endpoint (rather than a hand-configured public key) is deliberate: it's the same pattern
 * {@code oid4vp-demo-verifier}'s {@code IssuerKeyResolver} already uses to fetch a key over HTTP from
 * {@code oid4vp-demo-wallet}'s own {@code /issuer-jwks}.
 *
 * <p>Returns a pre-serialized {@code String} — see {@link IssuerMetadataController}'s Javadoc for why.
 */
@RestController
public class JwksController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final IssuerKeys keys;
    private final IssuerContextResolver issuers;

    public JwksController(ECKey issuerKey) {
        this(IssuerKeys.fixed(issuerKey, null), IssuerContextResolver.SINGLE_TENANT);
    }

    /** Publishes each tenant's own keys: the active one and those retired but still verifying what they signed. */
    public JwksController(IssuerKeys keys, IssuerContextResolver issuers) {
        this.keys = keys;
        this.issuers = issuers;
    }

    @GetMapping(value = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwks(jakarta.servlet.http.HttpServletRequest request) throws Exception {
        ObjectNode jwkSet = JsonNodeFactory.instance.objectNode();
        var array = jwkSet.putArray("keys");
        for (ECKey key : keys.verificationKeys(issuers.resolve(request))) {
            array.add(MAPPER.readTree(key.toPublicJWK().toJSONString()));
        }
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofHours(1))).body(jwkSet.toString());
    }
}
