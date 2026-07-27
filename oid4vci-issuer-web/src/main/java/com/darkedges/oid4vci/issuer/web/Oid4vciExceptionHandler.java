package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps {@link Oid4vciException} to the OAuth2-shaped {@code {"error": "..."}} JSON body OID4VCI's Token
 * and Credential Endpoints use, with the HTTP status RFC 6749/OID4VCI expects per error code.
 *
 * <p>Returns a pre-serialized {@code String} — see {@link IssuerMetadataController}'s Javadoc for why.
 */
@RestControllerAdvice
public class Oid4vciExceptionHandler {

    @ExceptionHandler(Oid4vciException.class)
    public ResponseEntity<String> handle(Oid4vciException e) {
        HttpStatus status = e.errorCode() == Oid4vciErrorCode.INVALID_TOKEN ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST;
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("error", e.errorCode().value());
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body.toString());
    }
}
