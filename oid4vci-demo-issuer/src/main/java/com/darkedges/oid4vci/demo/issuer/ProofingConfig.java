package com.darkedges.oid4vci.demo.issuer;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Wiring for the identity-proofing flow.
 *
 * <p>The {@link Clock} is a bean rather than {@code Clock.systemUTC()} inline — which is what
 * {@code Oid4vciIssuerAutoConfiguration} does — because every expiry rule here (a session's TTL, a
 * pre-authorized code's, an MRZ two-digit year's century) is only testable against a clock that can
 * be moved.
 */
@Configuration
@EnableConfigurationProperties(ProofingProperties.class)
public class ProofingConfig {

    @Bean
    public Clock proofingClock() {
        return Clock.systemUTC();
    }

    @Bean
    public ProofingSessionStore proofingSessionStore() {
        return new InMemoryProofingSessionStore();
    }

    @Bean
    public PassportClaimsMapper passportClaimsMapper(Clock clock) {
        return new PassportClaimsMapper(clock);
    }
}
