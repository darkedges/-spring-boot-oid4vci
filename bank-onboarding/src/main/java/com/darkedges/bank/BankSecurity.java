package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.*;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.nio.file.*;
import java.time.*;
import java.util.*;

@Configuration
public class BankSecurity {
    static boolean hasHrRole(Object roles) { return roles instanceof Collection<?> list && list.contains("bank-hr"); }
    static boolean hasHrAccess(org.springframework.security.oauth2.core.oidc.user.OidcUser user, String claim) {
        Object membership = user.getClaims().get(claim);
        // Accept scalar groups only when explicitly configured. The default roles
        // contract still requires an array; all matches remain exact.
        return hasHrRole(membership) || ("groups".equals(claim) && "bank-hr".equals(membership));
    }
    @Bean ECKey issuerSigningKey(@Value("${bank.signing-key-file}") String file) throws Exception {
        ECKey key = ECKey.parse(Files.readString(Path.of(file)));
        if (!key.isPrivate() || !com.nimbusds.jose.jwk.Curve.P_256.equals(key.getCurve())) throw new IllegalArgumentException("Bank signing key must be private");
        return key;
    }
    /**
     * The Journey API (JourneyApiController) accepts only a machine token: an AuthStack client-credentials access token issued by
     * bank.journey.issuer, for this API's audience and scope, to a client named in bank.journey.clients. Stateless, no cookies, no CSRF
     * (a bearer token is not sent by a browser on its own). With no issuer configured the API is off: every call is refused.
     */
    @Bean @Order(0) SecurityFilterChain journey(HttpSecurity http,
            @Value("${bank.journey.issuer:}") String issuer, @Value("${bank.journey.jwk-set-uri:}") String jwkSetUri,
            @Value("${bank.journey.audience:bank-journey}") String audience, @Value("${bank.journey.scope:bank.journey}") String scope,
            @Value("${bank.journey.clients:}") String clients) throws Exception {
        http.securityMatcher("/api/journey/**").csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS));
        if (issuer.isBlank()) return http.authorizeHttpRequests(a -> a.anyRequest().denyAll()).build();
        var decoder = journeyDecoder(issuer, jwkSetUri, audience, scope, clients);
        return http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .oauth2ResourceServer(o -> o.jwt(j -> j.decoder(decoder))).build();
    }
    static org.springframework.security.oauth2.jwt.JwtDecoder journeyDecoder(String issuer, String jwkSetUri, String audience, String scope, String clients) {
        var decoder = jwkSetUri.isBlank()
            ? org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withIssuerLocation(issuer).build()
            : org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
            org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer(issuer), journeyClaims(audience, scope, clients)));
        return decoder;
    }
    /** The audience, a scope and an allowed client, all required: a token for another API, or from another client, is refused. */
    static org.springframework.security.oauth2.core.OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> journeyClaims(String audience, String scope, String clients) {
        Set<String> allowed = new HashSet<>(Arrays.stream(clients.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList());
        var invalid = new org.springframework.security.oauth2.core.OAuth2Error("invalid_token", "Not a Journey API token", null);
        return jwt -> {
            Object scopes = jwt.getClaims().get("scope");
            boolean hasScope = scopes instanceof String s ? Arrays.asList(s.split(" ")).contains(scope) : scopes instanceof Collection<?> c && c.contains(scope);
            boolean hasAudience = jwt.getAudience() != null && jwt.getAudience().contains(audience);
            boolean allowedClient = allowed.contains(Objects.toString(jwt.getClaims().get("client_id"), ""));
            return hasScope && hasAudience && allowedClient
                ? org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success()
                : org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(invalid);
        };
    }
    @Bean @Order(1) SecurityFilterChain issuance(HttpSecurity http) throws Exception {
        return http.securityMatcher("/credential", "/token", "/nonce", "/.well-known/**", "/jwks", "/vct/**")
            .csrf(c -> c.disable()).authorizeHttpRequests(a -> a.requestMatchers("/credential").authenticated().anyRequest().permitAll())
            .oauth2ResourceServer(o -> o.jwt(j -> {})).build();
    }
    /** HR access only ever comes from the HR provider: a staff sign-in through AuthStack never grants it, whatever its token carries. */
    static boolean grantsHr(String registrationId, org.springframework.security.oauth2.core.oidc.user.OidcUser user, String claim) {
        return "hr".equals(registrationId) && hasHrAccess(user, claim);
    }
    @Bean @Order(2) SecurityFilterChain portal(HttpSecurity http, @Value("${bank.hr-claim:roles}") String hrClaim, StaffSignIn staffSignIn) throws Exception {
        OidcUserService delegate = new OidcUserService();
        return http.csrf(c -> c.ignoringRequestMatchers("/vp/response/**"))
            .authorizeHttpRequests(a -> a.requestMatchers("/hr", "/hr/**").hasAuthority("BANK_HR").requestMatchers("/account/**").authenticated().anyRequest().permitAll())
            .exceptionHandling(e -> e.accessDeniedHandler((request, response, exception) -> {
                response.setStatus(403);
                request.getRequestDispatcher("/account/access").forward(request, response);
            }))
            .logout(l -> l.invalidateHttpSession(true).clearAuthentication(true).deleteCookies("JSESSIONID").logoutSuccessUrl("/"))
            // HR pages send a signed-out browser straight to the HR provider, as they did when it was the only one (with a second, staff,
            // registration Spring would otherwise show its own choice page). A staff sign-in goes to /oauth2/authorization/staff.
            .oauth2Login(o -> o.loginPage("/oauth2/authorization/hr").failureUrl("/?signin=failed")
                .successHandler(staffSignIn.successHandler())
                .userInfoEndpoint(u -> u.oidcUserService(request -> {
                var user = delegate.loadUser(request);
                var authorities = new ArrayList<org.springframework.security.core.GrantedAuthority>(user.getAuthorities());
                if (grantsHr(request.getClientRegistration().getRegistrationId(), user, hrClaim)) authorities.add(new SimpleGrantedAuthority("BANK_HR"));
                return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo());
            }))).build();
    }
    // Internal authorization metadata lives in PostgreSQL, never in credential claims.
    @Bean(name="sdJwtVcCredentialIssuanceService") CredentialIssuanceService staffIssuance(ECKey key, JdbcTemplate db, @Value("${bank.base-url}") String canonicalBase) {
        var delegate = new SdJwtVcCredentialIssuanceService(key, List.of(), Duration.ofDays(30), Clock.systemUTC());
        return new CredentialIssuanceService() {
            public CredentialFormat format() { return CredentialFormat.DC_SD_JWT; }
            public String issue(CredentialConfiguration config, Map<String,String> claims, ECKey holder, String base) {
                if (!canonicalBase.equals(base)) throw new IllegalArgumentException("Use the canonical bank issuer URL"); UUID id = UUID.fromString(claims.get("staff_id"));
                return new org.springframework.transaction.support.TransactionTemplate(new org.springframework.jdbc.datasource.DataSourceTransactionManager(Objects.requireNonNull(db.getDataSource()))).execute(tx -> {
                    var hire = db.queryForMap("select * from bank_hire where id=? for update", id);
                    if (!Set.of("APPROVED", "ACTIVE").contains(hire.get("status"))) throw new com.darkedges.oid4vci.core.error.Oid4vciException(com.darkedges.oid4vci.core.error.Oid4vciErrorCode.INVALID_TOKEN, "Staff issuance is no longer authorized");
                    if (!db.queryForList("select id from bank_hire where previous_hire_id=?",id).isEmpty()) throw new com.darkedges.oid4vci.core.error.Oid4vciException(com.darkedges.oid4vci.core.error.Oid4vciErrorCode.INVALID_TOKEN,"Staff issuance has been superseded by a new attempt");
                    try {
                        if (!ECKey.parse((String) hire.get("holder_jwk")).computeThumbprint().equals(holder.computeThumbprint())) throw new IllegalArgumentException("Wrong holder key");
                    } catch (java.text.ParseException | com.nimbusds.jose.JOSEException e) { throw new IllegalArgumentException("Invalid holder key", e); }
                    if (hire.get("issued_credential") != null) return (String) hire.get("issued_credential");
                    String result = delegate.issue(config, claims, holder, base);
                    db.update("update bank_hire set status='ACTIVE',issued_credential=? where id=?", result, id);
                    db.update("insert into bank_audit(hire_id,action,actor) values (?,'ISSUED','issuer')", id);
                    return result;
                });
            }
        };
    }
}
