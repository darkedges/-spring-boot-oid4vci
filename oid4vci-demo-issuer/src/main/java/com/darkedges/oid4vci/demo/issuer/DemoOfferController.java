package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferWriter;
import com.darkedges.oid4vci.core.offer.Grants;
import com.darkedges.oid4vci.core.offer.PreAuthorizedCodeGrant;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.web.RequestBaseUrl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Demo-only: seeds a pre-authorized code + concrete claim values (standing in for a real
 * enrollment/KYC step) and hands back a Credential Offer, so the whole pre-authorized_code flow can be
 * driven end to end without a separate identity-proofing system. Not a pattern to copy for a real
 * Issuer — same spirit as oid4vp-demo-verifier's {@code DemoConfigController}.
 *
 * <p>Returns a pre-serialized {@code String} — see {@code IssuerMetadataController}'s Javadoc
 * (oid4vci-issuer-web) for why {@code ObjectNode} can't be returned directly under Spring Boot 4.1.
 */
@RestController
public class DemoOfferController {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final PreAuthorizedCodeStore codeStore;
    private final CredentialIssuerMetadataTemplate template;

    public DemoOfferController(PreAuthorizedCodeStore codeStore, CredentialIssuerMetadataTemplate template) {
        this.codeStore = codeStore;
        this.template = template;
    }

    @GetMapping(value = "/demo/offer", produces = MediaType.APPLICATION_JSON_VALUE)
    public String offer(HttpServletRequest servletRequest) {
        CredentialIssuerMetadata metadata = template.resolve(RequestBaseUrl.resolve(servletRequest));
        List<String> configurationIds = List.copyOf(metadata.credentialConfigurationsSupported().keySet());
        String code = randomCode();

        codeStore.save(code, new PreAuthorizedCodeSession(
                configurationIds, Optional.empty(),
                Map.of("given_name", "Jane", "family_name", "Doe"),
                Instant.now().plus(Duration.ofMinutes(10))));

        CredentialOffer offer = new CredentialOffer(
                metadata.credentialIssuer(), configurationIds,
                Optional.of(new Grants(Optional.empty(), Optional.of(new PreAuthorizedCodeGrant(code, Optional.empty(), Optional.empty())))));

        return CredentialOfferWriter.write(offer).toString();
    }

    /** 32 bytes, not 16 — see {@code AuthorizationEndpointController#randomCode}'s Javadoc for why a
     * shorter code can fail the OpenID Conformance Suite's entropy check even at full cryptographic
     * randomness. No such check currently targets {@code pre-authorized_code} specifically, but there's no
     * reason for this code to be weaker than the {@code authorization_code} grant's. */
    private static String randomCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
