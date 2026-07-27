package com.darkedges.oid4vci.core.metadata;

import com.darkedges.oid4vci.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trips {@link CredentialIssuerMetadataReader}/{@link CredentialIssuerMetadataWriter}.
 *
 * <p>Unlike {@code CredentialOfferRoundTripTest}'s fixture (a verbatim quote of the spec's own Section
 * 4.1.1 example, confirmed by independently fetching the spec text), the fixture here is a
 * representative example rather than a byte-for-byte spec quote — repeated attempts to fetch OID4VCI
 * 1.0's Appendix A.2/A.3 worked examples returned only truncated spec text. Its field-level shapes are
 * still independently confirmed rather than guessed: {@code proof_types_supported} being an object keyed
 * by proof type name (not a plain array, as an earlier draft of this fixture incorrectly assumed) was
 * confirmed against two real-world Credential Issuer Metadata documents (Android Developers' hardware
 * attestation docs, GOV.UK Wallet's issuer metadata docs) before this model/fixture was written.
 */
class CredentialIssuerMetadataRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parsesBothCredentialConfigurations() {
        JsonNode json = FixtureLoader.readJson("credential_issuer_metadata.json");

        CredentialIssuerMetadata metadata = CredentialIssuerMetadataReader.read(json);

        assertThat(metadata.credentialIssuer().toString()).isEqualTo("https://credential-issuer.example.com");
        assertThat(metadata.credentialEndpoint().toString()).isEqualTo("https://credential-issuer.example.com/credential");
        assertThat(metadata.nonceEndpoint()).isPresent();
        assertThat(metadata.credentialConfigurationsSupported()).hasSize(2);

        CredentialConfiguration sdJwt = metadata.credentialConfigurationsSupported().get("UniversityDegreeCredential");
        assertThat(sdJwt).isInstanceOf(SdJwtVcCredentialConfiguration.class);
        assertThat(sdJwt.format()).isEqualTo(CredentialFormat.DC_SD_JWT);
        assertThat(((SdJwtVcCredentialConfiguration) sdJwt).vct())
                .isEqualTo("https://credential-issuer.example.com/vct/UniversityDegree");
        assertThat(sdJwt.claims()).hasSize(2);
        assertThat(sdJwt.proofTypesSupported().get(ProofType.JWT).proofSigningAlgValuesSupported())
                .containsExactly("ES256");

        CredentialConfiguration mdoc = metadata.credentialConfigurationsSupported().get("org.iso.18013.5.1.mDL");
        assertThat(mdoc).isInstanceOf(MsoMdocCredentialConfiguration.class);
        assertThat(mdoc.format()).isEqualTo(CredentialFormat.MSO_MDOC);
        assertThat(((MsoMdocCredentialConfiguration) mdoc).doctype()).isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void writingThenReadingBackProducesAnEquivalentMetadataDocument() throws Exception {
        JsonNode original = FixtureLoader.readJson("credential_issuer_metadata.json");
        CredentialIssuerMetadata metadata = CredentialIssuerMetadataReader.read(original);

        JsonNode written = CredentialIssuerMetadataWriter.write(metadata);
        CredentialIssuerMetadata reparsed = CredentialIssuerMetadataReader.read(written);

        assertThat(reparsed).isEqualTo(metadata);
        assertThat(MAPPER.readTree(MAPPER.writeValueAsString(written))).isEqualTo(original);
    }
}
