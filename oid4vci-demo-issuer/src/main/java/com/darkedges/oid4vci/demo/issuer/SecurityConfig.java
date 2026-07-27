package com.darkedges.oid4vci.demo.issuer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Per the project README: the Token/Nonce/Metadata/Offer endpoints need no authentication at all (minting
 * a token is business logic, not an authentication act); the Credential Endpoint is protected by a
 * standard OAuth2 bearer access token via {@code oauth2ResourceServer()} — this app applies that
 * explicitly, since {@code oid4vci-spring-boot-autoconfigure} deliberately never does.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/.well-known/**", "/credential-offer/**", "/token", "/nonce", "/jwks", "/demo/**",
                                "/", "/index.html")
                        .permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}));
        return http.build();
    }
}
