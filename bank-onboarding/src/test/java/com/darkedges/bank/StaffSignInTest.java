package com.darkedges.bank;

import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Staff sign-in through AuthStack: the staff id comes from the ID token's email, and the bank's own record decides. */
class StaffSignInTest {
    static final UUID STAFF = UUID.fromString("5f0c2a54-8a52-4c86-9f3e-2b1d6c0e7a11");
    JdbcTemplate db; StaffSignIn signIn;

    @BeforeEach void setUp() {
        db = mock(JdbcTemplate.class);
        signIn = new StaffSignIn(db, "staff.bank.example");
    }

    static OAuth2AuthenticationToken token(String registration, Map<String, Object> claims) {
        var all = new HashMap<String, Object>(Map.of("sub", "authstack-user-1", "iss", "https://as.example/env/as"));
        all.putAll(claims);
        var user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), new OidcIdToken("t", Instant.now(), Instant.now().plusSeconds(60), all));
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), registration);
    }

    @Test void readsTheStaffIdOnlyFromAnAddressInTheStaffDomain() {
        assertThat(signIn.staffIdFrom("staff-" + STAFF + "@staff.bank.example")).contains(STAFF);
        assertThat(signIn.staffIdFrom("STAFF-" + STAFF.toString().toUpperCase() + "@Staff.Bank.Example")).contains(STAFF);
        assertThat(signIn.staffIdFrom("staff-" + STAFF + "@evil.example")).isEmpty();
        assertThat(signIn.staffIdFrom("staff-" + STAFF + "@staff.bank.example.evil.example")).isEmpty();
        assertThat(signIn.staffIdFrom("staff-not-a-uuid@staff.bank.example")).isEmpty();
        assertThat(signIn.staffIdFrom("ada@staff.bank.example")).isEmpty();
        assertThat(signIn.staffIdFrom(null)).isEmpty();
    }

    @Test void theIdentityNamesThePersonAndTheSessionIsTheirCurrentAttempt() throws Exception {
        UUID person = UUID.fromString("0b1c2d3e-0000-4000-8000-000000000001");
        when(db.queryForList(eq(DirectoryOutbox.CURRENT_ATTEMPT), eq(UUID.class), eq(person))).thenReturn(List.of(STAFF));
        when(db.queryForObject(anyString(), eq(Integer.class), eq(STAFF))).thenReturn(1);
        var request = new MockHttpServletRequest(); var response = new MockHttpServletResponse();
        request.getSession(true);
        signIn.successHandler().onAuthenticationSuccess(request, response, token("staff", Map.of("email", "staff-" + person + "@staff.bank.example")));
        assertThat(response.getRedirectedUrl()).isEqualTo("/staff");
        assertThat(request.getSession().getAttribute("staff")).isEqualTo(STAFF.toString());
    }

    @Test void anActiveStaffMemberGetsAStaffSessionAndNoSignedInPrincipal() throws Exception {
        when(db.queryForList(eq(DirectoryOutbox.CURRENT_ATTEMPT), eq(UUID.class), eq(STAFF))).thenReturn(List.of(STAFF));
        when(db.queryForObject(anyString(), eq(Integer.class), eq(STAFF))).thenReturn(1);
        var request = new MockHttpServletRequest(); var response = new MockHttpServletResponse();
        request.getSession(true).setAttribute("SPRING_SECURITY_CONTEXT", "previous");
        signIn.successHandler().onAuthenticationSuccess(request, response, token("staff", Map.of("email", "staff-" + STAFF + "@staff.bank.example")));
        assertThat(response.getRedirectedUrl()).isEqualTo("/staff");
        assertThat(request.getSession().getAttribute("staff")).isEqualTo(STAFF.toString());
        assertThat(request.getSession().getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
    }

    @Test void anInactiveOrSupersededStaffMemberOrAStrangerIsRefused() throws Exception {
        when(db.queryForObject(anyString(), eq(Integer.class), eq(STAFF))).thenReturn(0);
        for (var claims : List.<Map<String, Object>>of(Map.of("email", "staff-" + STAFF + "@staff.bank.example"), Map.of("email", "someone@example.com"), Map.of())) {
            var request = new MockHttpServletRequest(); var response = new MockHttpServletResponse();
            signIn.successHandler().onAuthenticationSuccess(request, response, token("staff", claims));
            assertThat(response.getRedirectedUrl()).isEqualTo("/?staff=refused");
            assertThat(request.getSession().getAttribute("staff")).isNull();
        }
    }

    @Test void anHrSignInCarriesOnAsBefore() throws Exception {
        var request = new MockHttpServletRequest(); var response = new MockHttpServletResponse();
        signIn.successHandler().onAuthenticationSuccess(request, response, token("hr", Map.of("email", "staff-" + STAFF + "@staff.bank.example")));
        assertThat(response.getRedirectedUrl()).isEqualTo("/");
        assertThat(request.getSession().getAttribute("staff")).isNull();
        verifyNoInteractions(db);
    }

    @Test void onlyTheHrProviderCanGrantHrAccess() {
        var withRole = (DefaultOidcUser) token("staff", Map.of("roles", List.of("bank-hr"))).getPrincipal();
        assertThat(BankSecurity.grantsHr("hr", withRole, "roles")).isTrue();
        assertThat(BankSecurity.grantsHr("staff", withRole, "roles")).isFalse();
    }
}
