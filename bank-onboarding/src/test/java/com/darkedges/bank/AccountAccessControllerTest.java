package com.darkedges.bank;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.ui.ExtendedModelMap;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;

class AccountAccessControllerTest {
    private ExtendedModelMap render(Object roles, boolean hr) {
        var claims = new HashMap<String,Object>();
        claims.put("sub", "fixture-user");
        claims.put("private_claim", "must-not-be-exposed");
        if (roles != null) claims.put("roles", roles);
        var token = new OidcIdToken("must-not-be-exposed", Instant.now(), Instant.now().plusSeconds(60), claims);
        var authorities = hr ? List.of(new SimpleGrantedAuthority("BANK_HR")) : List.of(new SimpleGrantedAuthority("OIDC_USER"));
        var user = new DefaultOidcUser(authorities, token);
        var auth = new UsernamePasswordAuthenticationToken(user, null, authorities);
        var model = new ExtendedModelMap();
        assertThat(new AccountAccessController(org.mockito.Mockito.mock(org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository.class), false, "roles").access(auth, new org.springframework.mock.web.MockHttpServletRequest(), model)).isEqualTo("account-access");
        assertThat(model).doesNotContainKeys("token", "private_claim", "sub");
        return model;
    }
    @Test void showsActualRoleValuesWithoutGrantingAccess() {
        var model=render(List.of("CN=Bank HR,OU=Groups,DC=example"),false);
        assertThat(model.get("roles")).isEqualTo(List.of("CN=Bank HR,OU=Groups,DC=example"));
        assertThat(model.get("hrAccess")).isEqualTo(false);
    }
    @Test void distinguishesMissingAndMalformedRoles() {
        assertThat(render(null,false).get("rolesPresent")).isEqualTo(false);
        var malformed=render("bank-hr",false);
        assertThat(malformed.get("rolesPresent")).isEqualTo(true);
        assertThat(malformed.get("rolesArray")).isEqualTo(false);
        assertThat(malformed.get("hrAccess")).isEqualTo(false);
    }
    @Test void reportsExistingAuthority() { assertThat(render(List.of("bank-hr"),true).get("hrAccess")).isEqualTo(true); }
}
