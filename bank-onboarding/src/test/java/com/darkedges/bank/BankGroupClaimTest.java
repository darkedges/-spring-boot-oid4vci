package com.darkedges.bank;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.ui.ExtendedModelMap;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class BankGroupClaimTest {
    private DefaultOidcUser user(Object groups) {
        var claims = new HashMap<String,Object>();
        claims.put("sub", "fixture-user");
        if (groups != null) claims.put("groups", groups);
        var token = new OidcIdToken("fixture-token",Instant.now(),Instant.now().plusSeconds(60),claims);
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")),token);
    }
    @Test void acceptsExactScalarOrArrayGroupsWhenConfigured() {
        assertThat(BankSecurity.hasHrAccess(user("bank-hr"),"groups")).isTrue();
        assertThat(BankSecurity.hasHrAccess(user(List.of("staff","bank-hr")),"groups")).isTrue();
    }
    @Test void doesNotImplicitlyFallbackFromRolesToGroups() {
        assertThat(BankSecurity.hasHrAccess(user("bank-hr"),"roles")).isFalse();
        assertThat(BankSecurity.hasHrAccess(user(List.of("bank-hr")),"roles")).isFalse();
    }
    @Test void rejectsMissingOrInexactMembership() {
        for (Object value : Arrays.asList(null,"BANK-HR","prefix-bank-hr","bank-hr,staff","CN=bank-hr,OU=Groups",List.of("staff"))) {
            assertThat(BankSecurity.hasHrAccess(user(value),"groups")).isFalse();
        }
    }
    @Test void accessPageShowsConfiguredScalarGroup() {
        var user=user("bank-hr");
        var authentication=new OAuth2AuthenticationToken(user,user.getAuthorities(),"hr");
        var model=new ExtendedModelMap();
        new AccountAccessController(mock(OAuth2AuthorizedClientRepository.class),false,"groups").access(authentication,new MockHttpServletRequest(),model);
        assertThat(model.get("hrClaim")).isEqualTo("groups");
        assertThat(model.get("rolesPresent")).isEqualTo(true);
        assertThat(model.get("rolesArray")).isEqualTo(true);
        assertThat(model.get("roles")).isEqualTo(List.of("bank-hr"));
    }
}
