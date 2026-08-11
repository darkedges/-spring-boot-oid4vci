package com.darkedges.oid4vci.core.metadata;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialIssuerMetadataTemplateTest {

    @Test
    void resolvesAnIssuerRelativeVctAgainstTheRequestsBaseUrl() {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.empty(),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "/vct/UniversityDegreeCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));

        CredentialIssuerMetadata metadata = template.resolve("https://issuer.zkp.au");

        SdJwtVcCredentialConfiguration resolved = (SdJwtVcCredentialConfiguration)
                metadata.credentialConfigurationsSupported().get("UniversityDegreeCredential");
        assertThat(resolved.vct()).isEqualTo("https://issuer.zkp.au/vct/UniversityDegreeCredential");
    }

    @Test
    void leavesAnAlreadyAbsoluteVctUnchanged() {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.empty(),
                Map.of("UniversityDegreeCredential", new SdJwtVcCredentialConfiguration(
                        "https://type.example.org/UniversityDegree", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));

        CredentialIssuerMetadata metadata = template.resolve("https://issuer.zkp.au");

        SdJwtVcCredentialConfiguration resolved = (SdJwtVcCredentialConfiguration)
                metadata.credentialConfigurationsSupported().get("UniversityDegreeCredential");
        assertThat(resolved.vct()).isEqualTo("https://type.example.org/UniversityDegree");
    }

    @Test
    void resolvingDoesNotDisturbNonSdJwtConfigurations() {
        CredentialIssuerMetadataTemplate template = new CredentialIssuerMetadataTemplate(
                "/credential", Optional.empty(),
                Map.of("org.iso.18013.5.1.mDL", new MsoMdocCredentialConfiguration(
                        "org.iso.18013.5.1.mDL", List.of(), Map.of(), List.of(), List.of(), Optional.empty())));

        CredentialIssuerMetadata metadata = template.resolve("https://issuer.zkp.au");

        assertThat(metadata.credentialConfigurationsSupported().get("org.iso.18013.5.1.mDL"))
                .isInstanceOf(MsoMdocCredentialConfiguration.class);
    }
}
