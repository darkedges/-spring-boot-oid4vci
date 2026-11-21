package com.darkedges.oid4vci.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vci.core.metadata.AuthorizationServerMetadataTemplate;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.issuer.ClientAttestationTrustAnchor;
import com.darkedges.oid4vci.issuer.ClientAttestationTrustAnchors;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerMetadataTemplates;
import com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerAutoConfiguration;
import com.darkedges.oid4vci.spring.boot.autoconfigure.Oid4vciIssuerProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.ECKey;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * A tenant's issuer settings, as kept in its {@code settings} document and edited from the AuthStack console:
 * <pre>
 * {
 *   "credentialConfigurationsSupported": { ... },     what it issues (OID4VCI credential_configurations_supported); else the deployment's
 *   "batchCredentialIssuanceMaxSize": 3,              else the deployment's
 *   "clientAttestation": {                            the Wallet Provider it trusts for attest_jwt_client_auth; else the deployment's
 *     "trustedIssuer": "https://wallet-provider.example",
 *     "trustedIssuerKey": { "kty": "EC", ... }        its public key
 *   }
 * }
 * </pre>
 * Each tenant's metadata and trust are built from these, and rebuilt when its settings change.
 */
public final class TenantIssuerSettings implements IssuerMetadataTemplates, ClientAttestationTrustAnchors {

    public static final String CONFIGURATIONS = "credentialConfigurationsSupported";
    public static final String BATCH = "batchCredentialIssuanceMaxSize";
    public static final String CLIENT_ATTESTATION = "clientAttestation";

    private record Built(Instant version, CredentialIssuerMetadataTemplate credentialIssuer,
                         Optional<ClientAttestationTrustAnchor> anchor, AuthorizationServerMetadataTemplate authorizationServer) {}

    private final TenantRepository tenants;
    private final Oid4vciIssuerProperties properties;
    private final Supplier<CredentialIssuerMetadataTemplate> deploymentTemplate;
    private final Supplier<Optional<ClientAttestationTrustAnchor>> deploymentAnchor;
    private final Supplier<Boolean> authorizationCodeSupported;
    private final Map<String, Built> built = new ConcurrentHashMap<>();

    public TenantIssuerSettings(TenantRepository tenants, Oid4vciIssuerProperties properties,
                                Supplier<CredentialIssuerMetadataTemplate> deploymentTemplate,
                                Supplier<Optional<ClientAttestationTrustAnchor>> deploymentAnchor,
                                Supplier<Boolean> authorizationCodeSupported) {
        this.tenants = tenants;
        this.properties = properties;
        this.deploymentTemplate = deploymentTemplate;
        this.deploymentAnchor = deploymentAnchor;
        this.authorizationCodeSupported = authorizationCodeSupported;
    }

    @Override
    public CredentialIssuerMetadataTemplate credentialIssuer(IssuerContext context) {
        return built(context).credentialIssuer();
    }

    @Override
    public Optional<AuthorizationServerMetadataTemplate> authorizationServer(IssuerContext context) {
        return Optional.of(built(context).authorizationServer());
    }

    @Override
    public Optional<ClientAttestationTrustAnchor> forContext(IssuerContext context) {
        return built(context).anchor();
    }

    private Built built(IssuerContext context) {
        Tenant tenant = tenants.findById(context.tenantId())
                .orElseThrow(() -> new IllegalStateException("no tenant " + context.tenantId()));
        Built current = built.get(tenant.id());
        if (current != null && current.version().equals(tenant.updatedAt())) return current;
        Built fresh = build(tenant);
        built.put(tenant.id(), fresh);
        return fresh;
    }

    private Built build(Tenant tenant) {
        ObjectNode settings = tenant.settings();
        CredentialIssuerMetadataTemplate template;
        if (settings.hasNonNull(CONFIGURATIONS) || settings.hasNonNull(BATCH)) {
            JsonNode configurations = settings.hasNonNull(CONFIGURATIONS) ? settings.get(CONFIGURATIONS) : null;
            template = Oid4vciIssuerAutoConfiguration.credentialIssuerMetadataTemplate(
                    configurations != null ? configurations : deploymentConfigurations(),
                    settings.hasNonNull(BATCH) ? settings.get(BATCH).asInt() : properties.getBatchCredentialIssuanceMaxSize(),
                    properties);
        } else {
            template = deploymentTemplate.get();
        }
        Optional<ClientAttestationTrustAnchor> anchor = anchor(settings).or(deploymentAnchor);
        AuthorizationServerMetadataTemplate as = Oid4vciIssuerAutoConfiguration.authorizationServerMetadataTemplate(
                anchor.isPresent(), authorizationCodeSupported.get(), Optional.ofNullable(properties.getAttestationChallengeEndpointPath()));
        return new Built(tenant.updatedAt(), template, anchor, as);
    }

    private JsonNode deploymentConfigurations() {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readTree(properties.getCredentialConfigurationsSupported());
        } catch (Exception e) {
            throw new IllegalStateException("oid4vci.issuer.credential-configurations-supported is not JSON", e);
        }
    }

    static Optional<ClientAttestationTrustAnchor> anchor(ObjectNode settings) {
        JsonNode attestation = settings.get(CLIENT_ATTESTATION);
        if (attestation == null || attestation.isNull()) return Optional.empty();
        try {
            return Optional.of(new ClientAttestationTrustAnchor(attestation.path("trustedIssuer").asText(),
                    ECKey.parse(attestation.path("trustedIssuerKey").toString())));
        } catch (java.text.ParseException e) {
            throw new IllegalStateException("unreadable clientAttestation.trustedIssuerKey", e);
        }
    }

    /** What's wrong with these issuer settings, if anything: used by the console's admin API before saving. */
    public static List<String> problems(ObjectNode settings, Oid4vciIssuerProperties properties) {
        List<String> problems = new ArrayList<>();
        JsonNode configurations = settings.get(CONFIGURATIONS);
        if (configurations != null && !configurations.isNull()) {
            if (!configurations.isObject() || configurations.isEmpty()) {
                problems.add("\"" + CONFIGURATIONS + "\" must be an object naming at least one credential configuration");
            } else {
                try {
                    Oid4vciIssuerAutoConfiguration.credentialIssuerMetadataTemplate(configurations, null, properties);
                } catch (RuntimeException e) {
                    problems.add("\"" + CONFIGURATIONS + "\" is not valid: " + e.getMessage());
                }
            }
        }
        JsonNode batch = settings.get(BATCH);
        if (batch != null && !batch.isNull() && (!batch.canConvertToInt() || batch.asInt() < 2 || batch.asInt() > 100)) {
            // OID4VCI: batch_size MUST be 2 or greater (1 is no batch at all; leave the setting out).
            problems.add("\"" + BATCH + "\" must be a whole number from 2 to 100");
        }
        JsonNode attestation = settings.get(CLIENT_ATTESTATION);
        if (attestation != null && !attestation.isNull()) {
            if (attestation.path("trustedIssuer").asText("").isBlank()) {
                problems.add("\"" + CLIENT_ATTESTATION + ".trustedIssuer\" is required");
            }
            try {
                ECKey key = ECKey.parse(attestation.path("trustedIssuerKey").toString());
                if (key.isPrivate()) problems.add("\"" + CLIENT_ATTESTATION + ".trustedIssuerKey\" must be a public key only");
            } catch (java.text.ParseException e) {
                problems.add("\"" + CLIENT_ATTESTATION + ".trustedIssuerKey\" must be an EC public JWK");
            }
        }
        return problems;
    }
}
