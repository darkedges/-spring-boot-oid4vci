package com.darkedges.oid4vci.demo.wallet;

import com.darkedges.oid4vci.wallet.WalletBindingKeyResolver;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Generates a fresh EC key pair for every credential-binding request — a real Wallet would want a
 * distinct key per credential instance for unlinkability; there's no reason for a demo not to follow the
 * same convention. */
@Configuration
public class DemoWalletKeyConfig {

    @Bean
    public WalletBindingKeyResolver walletBindingKeyResolver() {
        return credentialConfigurationId -> {
            try {
                return new ECKeyGenerator(Curve.P_256).generate();
            } catch (JOSEException e) {
                throw new IllegalStateException("failed to generate a wallet binding key", e);
            }
        };
    }
}
