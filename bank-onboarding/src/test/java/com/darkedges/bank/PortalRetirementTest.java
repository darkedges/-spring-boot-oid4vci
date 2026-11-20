package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.*;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.server.ResponseStatusException;
import java.nio.file.*;
import java.util.List;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** While the applicant journey runs in Authr and staff sign in through AuthStack, the portal's own pages for them are retired. */
class PortalRetirementTest {
    @TempDir Path dir;
    JdbcTemplate db; BankController bank;

    @BeforeEach void setUp() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).generate();
        var file = dir.resolve("passport.jwk"); Files.writeString(file, key.toPublicJWK().toJSONString());
        db = mock(JdbcTemplate.class);
        bank = new BankController(db, mock(PreAuthorizedCodeStore.class), key, "https://bank.example", "https://issuer.example", file.toString(), "Bank");
    }

    @SuppressWarnings("unchecked")
    void staffSignInThroughAuthStack(boolean on) {
        ObjectProvider<ClientRegistrationRepository> provider = mock(ObjectProvider.class);
        var staff = ClientRegistration.withRegistrationId("staff").clientId("c").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://bank.example/login/oauth2/code/staff").authorizationUri("https://as.example/a").tokenUri("https://as.example/t").build();
        when(provider.getIfAvailable()).thenReturn(on ? new InMemoryClientRegistrationRepository(staff) : null);
        bank.setClientRegistrations(provider);
    }

    @Test void anOldInvitationLinkOpensTheAuthrJourneyWithTheTokenInTheFragment() {
        bank.setApplicantEntry("authr", "https://signon.example/journey/bank-applicant");
        var session = new MockHttpSession();
        assertThat(bank.claim("the-token", session, new MockHttpServletRequest())).isEqualTo("redirect:https://signon.example/journey/bank-applicant#invite=the-token");
        assertThat(session.getAttribute("hire")).isNull();
        verifyNoInteractions(db);
    }

    @Test void thePortalsApplicantPagesAnswerNotFound() {
        bank.setApplicantEntry("authr", "https://signon.example/journey/bank-applicant");
        var session = new MockHttpSession(); session.setAttribute("hire", "5f0c2a54-8a52-4c86-9f3e-2b1d6c0e7a11");
        for (var page : List.<ThrowingCallable>of(() -> bank.progress(session, new ExtendedModelMap()), () -> bank.present(session, new ExtendedModelMap()), () -> bank.offer(session, new ExtendedModelMap()))) {
            assertThatThrownBy(page::call).isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(404));
        }
        verifyNoInteractions(db);
    }

    @Test void withThePortalAsTheEntryEverythingWorksAsBefore() {
        bank.setApplicantEntry("portal", "");
        when(db.queryForList(anyString(), any(Object[].class))).thenReturn(List.of());
        assertThatThrownBy(() -> bank.claim("unknown", new MockHttpSession(), new MockHttpServletRequest())).hasMessageContaining("Invitation is invalid or expired");
        verify(db).queryForList(anyString(), any(Object[].class));
    }

    @Test void theBankPagesStaffSignInIsRetiredOnlyWhileStaffSignInThroughAuthStack() {
        staffSignInThroughAuthStack(true);
        assertThatThrownBy(() -> bank.login(new MockHttpSession(), new ExtendedModelMap())).isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(404));
        staffSignInThroughAuthStack(false);
        when(db.queryForObject(anyString(), eq(java.sql.Timestamp.class), any(Object[].class))).thenReturn(java.sql.Timestamp.from(java.time.Instant.now().plusSeconds(600)));
        assertThat(bank.login(new MockHttpSession(), new ExtendedModelMap())).isEqualTo("presentation");
    }

    interface ThrowingCallable { void call() throws Exception; }
}
