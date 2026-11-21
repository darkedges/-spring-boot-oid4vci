package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.IssuerContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

/**
 * Which issuer a request is for. A single-tenant deployment uses {@link #SINGLE_TENANT}: the one tenant, on the URL the request
 * arrived on ({@link RequestBaseUrl}). A multi-tenant deployment resolves the tenant from the request's host or path.
 */
@FunctionalInterface
public interface IssuerContextResolver {

    /**
     * @throws org.springframework.web.server.ResponseStatusException 404 when no issuer is served on this URL
     */
    IssuerContext resolve(HttpServletRequest request);

    IssuerContextResolver SINGLE_TENANT = request -> IssuerContext.single(RequestBaseUrl.resolve(request));

    /** The current request's issuer, for code that has no request at hand (a {@code JwtDecoder}). Empty outside a request. */
    default Optional<IssuerContext> current() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) return Optional.empty();
        return Optional.of(resolve(attributes.getRequest()));
    }
}
