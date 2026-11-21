package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Verifies this issuer's own access tokens at the Credential Endpoint, for the issuer the request is for: signed (ES256) by one of
 * that tenant's published keys, unexpired, and naming that issuer as both {@code iss} and {@code aud}. A token another tenant issued
 * fails all three.
 *
 * <p>The issuer comes from the current request ({@link IssuerContextResolver#current()}). Outside a request there is no issuer to
 * check against: a single-tenant deployment then checks the signature and expiry only, as it always has; a multi-tenant one refuses.
 */
public final class IssuerAccessTokenDecoder implements JwtDecoder {

    private final IssuerKeys keys;
    private final IssuerContextResolver issuers;
    private final boolean requireIssuer;
    private final Map<String, JwtDecoder> decoders = new ConcurrentHashMap<>();

    /**
     * @param requireIssuer refuse tokens when no request names the issuer (multi-tenant deployments)
     */
    public IssuerAccessTokenDecoder(IssuerKeys keys, IssuerContextResolver issuers, boolean requireIssuer) {
        this.keys = keys;
        this.issuers = issuers;
        this.requireIssuer = requireIssuer;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        IssuerContext context;
        try {
            context = issuers.current().orElse(null);
        } catch (RuntimeException e) {
            throw new BadJwtException("no issuer is served here");
        }
        if (context == null && requireIssuer) throw new BadJwtException("no issuer to check this token against");
        IssuerContext keyContext = context != null ? context : IssuerContext.single("");
        List<ECKey> verificationKeys = keys.verificationKeys(keyContext);
        if (verificationKeys.isEmpty()) throw new BadJwtException("this issuer has no keys");
        String expectedIssuer = context == null ? null : context.issuerIdentifier();
        String cacheKey = keyContext.tenantId() + "|" + expectedIssuer + "|"
                + verificationKeys.stream().map(ECKey::getKeyID).collect(Collectors.joining(","));
        if (decoders.size() > 1_000) decoders.clear();
        return decoders.computeIfAbsent(cacheKey, ignored -> build(verificationKeys, expectedIssuer)).decode(token);
    }

    private static JwtDecoder build(List<ECKey> verificationKeys, String expectedIssuer) {
        JWKSet set = new JWKSet(verificationKeys.stream().map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK()).toList());
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(new ImmutableJWKSet<SecurityContext>(set))
                .jwsAlgorithm(SignatureAlgorithm.ES256)
                .build();
        if (expectedIssuer != null) {
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    JwtValidators.createDefaultWithIssuer(expectedIssuer), audience(expectedIssuer)));
        }
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> audience(String expected) {
        OAuth2Error error = new OAuth2Error("invalid_token", "The access token was not issued for this issuer", null);
        return jwt -> jwt.getAudience() != null && jwt.getAudience().contains(expected)
                ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(error);
    }
}
