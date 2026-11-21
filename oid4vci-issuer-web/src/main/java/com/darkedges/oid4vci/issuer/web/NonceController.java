package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.token.NonceResponse;
import com.darkedges.oid4vci.core.token.NonceResponseWriter;
import com.darkedges.oid4vci.issuer.NonceService;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** The Nonce Endpoint (OID4VCI 1.0, Section 7). Returns a pre-serialized {@code String} — see
 * {@link IssuerMetadataController}'s Javadoc for why. */
@RestController
public class NonceController {

    private final NonceService nonceService;
    private final IssuerContextResolver issuers;

    public NonceController(NonceService nonceService) {
        this(nonceService, IssuerContextResolver.SINGLE_TENANT);
    }

    public NonceController(NonceService nonceService, IssuerContextResolver issuers) {
        this.nonceService = nonceService;
        this.issuers = issuers;
    }

    @PostMapping(value = "${oid4vci.issuer.nonce-endpoint-path:/nonce}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> nonce(jakarta.servlet.http.HttpServletRequest request) {
        NonceResponse response = new NonceResponse(nonceService.issue(issuers.resolve(request)));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(NonceResponseWriter.write(response).toString());
    }
}
