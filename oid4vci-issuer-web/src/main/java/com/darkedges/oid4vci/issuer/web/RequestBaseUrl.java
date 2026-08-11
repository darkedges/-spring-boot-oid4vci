package com.darkedges.oid4vci.issuer.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Resolves the Issuer's own base URL (no trailing slash, no path) as the client actually reached it on a
 * given request — e.g. {@code https://issuer.zkp.au}, not whatever internal bind address/Docker network
 * alias the app happens to be listening on. This is what every issued document (Credential Issuer
 * Metadata, minted tokens' {@code iss}, issued credentials' {@code iss}, the DPoP {@code htu} check)
 * should be built from, since the same deployment may be reachable at more than one address.
 *
 * <p>Only correct when {@code server.forward-headers-strategy=framework} (or {@code native}) is set on
 * the consuming application: {@link ServletUriComponentsBuilder#fromContextPath} otherwise reflects the
 * request as the app's own servlet container saw it (e.g. the reverse proxy's internal upstream address),
 * not the {@code X-Forwarded-Proto}/{@code X-Forwarded-Host} headers a front door sets.
 */
public final class RequestBaseUrl {

    private RequestBaseUrl() {}

    public static String resolve(HttpServletRequest request) {
        String baseUrl = ServletUriComponentsBuilder.fromContextPath(request).build().toUriString();
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}
