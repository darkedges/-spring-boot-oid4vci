package com.darkedges.oid4vci.demo.issuer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Per the project README: the Authorize/Token/Nonce/Metadata/Offer endpoints need no authentication at all
 * (minting a token — or an authorization code — is business logic, not an authentication act, and there's
 * no login anywhere in this demo; see {@code AuthorizationEndpointController}'s Javadoc); the Credential
 * Endpoint is protected by a
 * standard OAuth2 bearer access token via {@code oauth2ResourceServer()} — this app applies that
 * explicitly, since {@code oid4vci-spring-boot-autoconfigure} deliberately never does.
 *
 * <p>{@code .dPoP(Customizer.withDefaults())} opts into Spring Security 7.1's native DPoP (RFC 9449)
 * resource-server support: when {@code TokenController} mints a sender-constrained access token (a
 * {@code cnf.jkt} claim, from a {@code DPoP} header on the token request — see
 * {@code DpopProofValidator}), that token can no longer be presented via the plain {@code Bearer} scheme
 * at all — confirmed live that {@code BearerTokenAuthenticationFilter} unconditionally refuses any
 * {@code cnf}-bearing JWT it authenticates outside the DPoP path, regardless of whether a DPoP proof was
 * even sent. The client must instead send {@code Authorization: DPoP <token>} plus a {@code DPoP: <proof>}
 * header; this native support verifies that proof (signature, {@code htm}/{@code htu}, {@code ath}
 * against the presented token, and the proof key's thumbprint against the token's {@code cnf.jkt}) before
 * the Credential Endpoint ever runs.
 *
 * <p>The {@code /proofing/**} endpoints (see {@code ProofingController}) are all permitted through
 * this chain, but they are not all open: {@code POST /proofing/result} authenticates its caller
 * against a shared secret in the controller itself, because the proofing service holds no bearer
 * token this resource server could validate. Listing it here lets it reach that check instead of
 * being turned away with a token challenge it can never answer — it is not a decision that the
 * endpoint needs no authentication.
 *
 * <p>{@code /error} must also be in the permitAll list. Any error a public endpoint hits (a 406 from
 * content negotiation, a 500, ...) makes the servlet container re-dispatch the request internally to
 * Spring Boot's {@code BasicErrorController} at {@code /error}; Spring Security re-evaluates authorization
 * for that dispatch same as any other request. Without {@code /error} explicitly permitted, that
 * re-evaluation falls through to {@code anyRequest().authenticated()}, and — since this chain also
 * configures an OAuth2 resource server — gets rewritten into a misleading {@code 401} with a
 * {@code WWW-Authenticate: Bearer} challenge, regardless of what the original error status was or that the
 * original endpoint was itself permitAll. Confirmed live: a plain {@code Accept: application/jwt} on the
 * (permitAll, unauthenticated) credential issuer metadata endpoint — which can't produce that
 * representation and would otherwise just 406 — came back as a 401 until this was added.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/.well-known/**", "/credential-offer/**", "/authorize", "/par", "/token", "/nonce",
                                "/challenge", "/jwks", "/vct/**", "/demo/**", "/", "/index.html", "/error",
                                // The Wallet's two calls. Starting a session asserts nothing, and
                                // collecting an offer is guarded by the retrieval secret issued at the
                                // start rather than by this filter chain -- there is no user identity
                                // here to authenticate against, only a bearer of that secret.
                                "/proofing/session", "/proofing/session/**")
                        .permitAll()
                        // Deliberately NOT listed above, and deliberately not under /demo/**, which is
                        // permitAll wholesale: POST /proofing/result is what decides the contents of an
                        // issued credential. Unauthenticated, it is claim injection -- anyone who could
                        // reach the host could mint a credential asserting any identity. It
                        // authenticates itself against a shared secret in ProofingController, so this
                        // chain must let it through to that check rather than to a bearer-token
                        // challenge it can never satisfy.
                        .requestMatchers("/proofing/result").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> {})
                        .dPoP(Customizer.withDefaults()));
        return http.build();
    }
}
