package com.darkedges.oid4vci.demo.wallet;

import com.darkedges.oid4vci.wallet.CredentialEndpointClient;
import com.darkedges.oid4vci.wallet.NonceEndpointClient;
import com.darkedges.oid4vci.wallet.PreAuthorizedTokenEndpointClient;
import com.darkedges.oid4vci.wallet.WalletBindingKeyResolver;
import com.darkedges.oid4vci.wallet.WalletIssuanceOrchestrator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class OrchestratorConfig {

    @Bean
    public WalletIssuanceOrchestrator walletIssuanceOrchestrator(
            PreAuthorizedTokenEndpointClient tokenClient, NonceEndpointClient nonceClient,
            CredentialEndpointClient credentialClient, WalletBindingKeyResolver keyResolver) {
        return new WalletIssuanceOrchestrator(tokenClient, nonceClient, credentialClient, keyResolver, Clock.systemUTC());
    }

    @Bean
    public MutableCredentialStore mutableCredentialStore() {
        return new MutableCredentialStore();
    }
}
