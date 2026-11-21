package com.darkedges.oid4vci.issuer.jdbc;

import com.darkedges.oid4vci.core.authorize.AuthorizationRequest;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferReader;
import com.darkedges.oid4vci.core.token.AuthorizationDetail;
import com.darkedges.oid4vci.issuer.AuthorizationCodeEntry;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The issuer's stores against a real PostgreSQL: set {@code OID4VCI_TEST_POSTGRES_URL}, for example
 * {@code jdbc:postgresql://localhost:55433/issuer?user=issuer&password=issuer}. Skipped otherwise.
 */
@EnabledIfEnvironmentVariable(named = "OID4VCI_TEST_POSTGRES_URL", matches = ".+")
class JdbcIssuerStoresTest {

    private DriverManagerDataSource dataSource;
    private JdbcClient jdbc;
    private IssuerEntryTable table;

    private static byte[] key() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return k;
    }

    @BeforeEach
    void setUp() {
        dataSource = new DriverManagerDataSource(System.getenv("OID4VCI_TEST_POSTGRES_URL"));
        jdbc = JdbcClient.create(dataSource);
        jdbc.sql("DROP TABLE IF EXISTS oid4vci_issuer_entry").update();
        var schema = new ResourceDatabasePopulator(new ClassPathResource("oid4vci-issuer-jdbc/schema-postgresql.sql"));
        schema.execute(dataSource);
        schema.execute(dataSource); // idempotent
        table = new IssuerEntryTable(jdbc, key());
    }

    private static PreAuthorizedCodeSession session() {
        return new PreAuthorizedCodeSession(List.of("Passport"), Optional.of("1234"),
                Map.of("given_name", "Jane", "document_number", "PA1234567"), Instant.now().plusSeconds(300));
    }

    @Test
    void aPreAuthorizedCodeIsStoredHashedAndEncryptedAndReadBackOnce() {
        var codes = new JdbcIssuerStores.PreAuthorizedCodes(table);
        String scoped = new IssuerContext("env-bank", "https://bank.issuer.test").scope("code-abc");
        codes.save(scoped, session());

        // Neither the code nor the claims can be read from the table.
        String dump = jdbc.sql("SELECT kind || key || encode(payload, 'escape') FROM oid4vci_issuer_entry").query(String.class).single();
        assertThat(dump).doesNotContain("code-abc").doesNotContain("Jane").doesNotContain("PA1234567");

        PreAuthorizedCodeSession back = codes.consume(scoped).orElseThrow();
        assertThat(back.claims()).containsEntry("document_number", "PA1234567");
        assertThat(back.expectedTxCode()).contains("1234");
        assertThat(back.credentialConfigurationIds()).containsExactly("Passport");
        assertThat(codes.consume(scoped)).isEmpty();
        // Another tenant's scoped key is another row.
        codes.save(scoped, session());
        assertThat(codes.consume(new IssuerContext("env-shop", "https://shop.issuer.test").scope("code-abc"))).isEmpty();
    }

    @Test
    void aCodeIsRedeemedOnceEvenWhenInstancesRaceForIt() throws Exception {
        var codes = new JdbcIssuerStores.PreAuthorizedCodes(table);
        codes.save("race", session());
        var pool = Executors.newFixedThreadPool(8);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            Callable<Boolean> attempt = () -> new JdbcIssuerStores.PreAuthorizedCodes(new IssuerEntryTable(jdbc, keyOf(table))).consume("race").isPresent();
            results.add(pool.submit(attempt));
        }
        int winners = 0;
        for (Future<Boolean> r : results) if (r.get()) winners++;
        pool.shutdown();
        assertThat(winners).isEqualTo(1);
    }

    private byte[] keyOf(IssuerEntryTable t) throws Exception {
        var field = IssuerEntryTable.class.getDeclaredField("key");
        field.setAccessible(true);
        return ((javax.crypto.spec.SecretKeySpec) field.get(t)).getEncoded();
    }

    @Test
    void authorizationCodesAndPushedRequestsRoundTrip() {
        var codes = new JdbcIssuerStores.AuthorizationCodes(table);
        codes.save("c1", new AuthorizationCodeEntry(session(), URI.create("https://wallet.example/cb"), Optional.of("challenge"), Optional.of("S256")));
        AuthorizationCodeEntry entry = codes.consume("c1").orElseThrow();
        assertThat(entry.redirectUri()).isEqualTo(URI.create("https://wallet.example/cb"));
        assertThat(entry.codeChallenge()).contains("challenge");
        assertThat(entry.session().claims()).containsEntry("given_name", "Jane");

        var par = new JdbcIssuerStores.PushedAuthorizationRequests(table);
        AuthorizationRequest request = new AuthorizationRequest("code", "wallet-1", URI.create("https://wallet.example/cb"),
                Optional.of("st"), Optional.of("ch"), Optional.of("S256"),
                List.of(new AuthorizationDetail("Passport", Optional.empty())), List.of("passport", "openid"));
        Instant expires = Instant.now().plusSeconds(60);
        par.save("urn:ietf:params:oauth:request_uri:abc", new PushedAuthorizationRequestEntry(request, expires));
        PushedAuthorizationRequestEntry back = par.consume("urn:ietf:params:oauth:request_uri:abc").orElseThrow();
        assertThat(back.request()).isEqualTo(request);
        assertThat(back.expiresAt()).isEqualTo(expires);
    }

    @Test
    void noncesAreSingleUseAndExpire() {
        var nonces = new JdbcIssuerStores.Nonces(table);
        Instant now = Instant.now();
        nonces.save("n1", now.plusSeconds(60));
        nonces.save("n2", now.minusSeconds(1));
        assertThat(nonces.consume("n1", now)).isTrue();
        assertThat(nonces.consume("n1", now)).isFalse();
        assertThat(nonces.consume("n2", now)).isFalse();
        assertThat(nonces.consume("never", now)).isFalse();
    }

    @Test
    void theClaimsBehindATokenAreReadUntilExpiryThenGone() {
        var claims = new JdbcIssuerStores.AccessTokenClaims(table);
        Instant now = Instant.now();
        claims.save("sub-1", Map.of("given_name", "Jane"), now.plusSeconds(60));
        assertThat(claims.find("sub-1", now)).contains(Map.of("given_name", "Jane"));
        assertThat(claims.find("sub-1", now)).isPresent();
        assertThat(claims.find("sub-1", now.plusSeconds(61))).isEmpty();
        assertThat(jdbc.sql("SELECT count(*) FROM oid4vci_issuer_entry").query(Integer.class).single()).isZero();
    }

    @Test
    void offersAreKeptForTheirTtl() throws Exception {
        CredentialOffer offer = CredentialOfferReader.read(new ObjectMapper().readTree(
                "{\"credential_issuer\":\"https://bank.issuer.test\",\"credential_configuration_ids\":[\"Passport\"],"
                        + "\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"x\"}}}"));
        new JdbcIssuerStores.CredentialOffers(table, Duration.ofHours(1), Clock.systemUTC()).save("o1", offer);
        assertThat(new JdbcIssuerStores.CredentialOffers(table, Duration.ofHours(1), Clock.systemUTC()).find("o1")).contains(offer);
        Clock later = Clock.offset(Clock.systemUTC(), Duration.ofHours(2));
        assertThat(new JdbcIssuerStores.CredentialOffers(table, Duration.ofHours(1), later).find("o1")).isEmpty();
    }

    @Test
    void replayRecordsRefuseAReusedJtiUntilItExpiresAndKeepNamespacesApart() {
        var dpop = new JdbcIssuerStores.ReplayRecords(table, JdbcIssuerStores.DPOP_JTI);
        var pop = new JdbcIssuerStores.ReplayRecords(table, JdbcIssuerStores.ATTESTATION_POP_JTI);
        Instant now = Instant.now();
        assertThat(dpop.recordUse("j1", now, now.plusSeconds(60))).isTrue();
        assertThat(dpop.recordUse("j1", now, now.plusSeconds(60))).isFalse();
        assertThat(pop.recordUse("j1", now, now.plusSeconds(60))).as("a separate namespace").isTrue();
        assertThat(dpop.recordUse("j1", now.plusSeconds(61), now.plusSeconds(120))).as("after expiry").isTrue();
    }

    @Test
    void anotherKeyOrAMovedRowCannotBeDecrypted() {
        var codes = new JdbcIssuerStores.PreAuthorizedCodes(table);
        codes.save("a", session());
        codes.save("b", session());
        codes.save("c", session());
        // Another deployment's key. (The single-use read removes the row even so: an entry nothing can read is of no use.)
        assertThatThrownBy(() -> new JdbcIssuerStores.PreAuthorizedCodes(new IssuerEntryTable(jdbc, key())).consume("c"))
                .isInstanceOf(IllegalStateException.class);
        // Copy b's payload onto a's row: it was bound to b.
        jdbc.sql("UPDATE oid4vci_issuer_entry SET payload = (SELECT payload FROM oid4vci_issuer_entry WHERE key = ?) WHERE key = ?")
                .params(IssuerEntryTable.hash("b"), IssuerEntryTable.hash("a")).update();
        assertThatThrownBy(() -> codes.consume("a")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void expiredEntriesAreSwept() {
        table.put(JdbcIssuerStores.NONCE, "old", null, Instant.now().minus(Duration.ofHours(1)));
        table.put(JdbcIssuerStores.NONCE, "new", null, Instant.now().plusSeconds(60));
        assertThat(table.sweep()).isEqualTo(1);
        assertThat(table.get(JdbcIssuerStores.NONCE, "new")).isPresent();
    }
}
