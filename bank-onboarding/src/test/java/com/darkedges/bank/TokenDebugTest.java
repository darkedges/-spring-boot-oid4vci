package com.darkedges.bank;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.*;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.ui.ExtendedModelMap;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class TokenDebugTest {
    record Fixture(OAuth2AuthenticationToken authentication, OAuth2AuthorizedClientRepository clients, MockHttpServletRequest request) {}
    private Fixture fixture(String accessToken) {
        var claims = Map.<String,Object>of("sub", "fixture-user", "roles", List.of("group-one"), "exp", Instant.now().plusSeconds(60));
        var idToken = new OidcIdToken("fixture-id-token", Instant.now(), Instant.now().plusSeconds(60), claims);
        var user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), idToken, new OidcUserInfo(Map.of("sub","fixture-user","groups",List.of("group-two"))));
        var authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "hr");
        var clients = mock(OAuth2AuthorizedClientRepository.class);
        var request = new MockHttpServletRequest();
        if (accessToken != null) {
            var registration = ClientRegistration.withRegistrationId("hr").clientId("fixture-client")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
                    .authorizationUri("https://issuer.example/authorize").tokenUri("https://issuer.example/token").build();
            var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.now().plusSeconds(60), Set.of("openid","profile"));
            var client = new OAuth2AuthorizedClient(registration,"fixture-user",token);
            when(clients.loadAuthorizedClient("hr",authentication,request)).thenReturn(client);
        }
        return new Fixture(authentication, clients, request);
    }
    @Test void disabledDoesNotLoadOrExposeTokens() {
        var f=fixture("fixture-access-token"); var model=new ExtendedModelMap();
        new AccountAccessController(f.clients(),false,"roles").access(f.authentication(),f.request(),model);
        assertThat(model.get("tokenDebugEnabled")).isEqualTo(false);
        assertThat(model).doesNotContainKeys("idTokenRaw","accessTokenRaw","idTokenClaims","userInfoClaims");
        verifyNoInteractions(f.clients());
    }
    @Test void enabledShowsCurrentSessionsTokensAndHandlesOpaqueAccessToken() {
        var f=fixture("opaque-fixture-access-token"); var model=new ExtendedModelMap();
        new AccountAccessController(f.clients(),true,"roles").access(f.authentication(),f.request(),model);
        assertThat(model.get("idTokenRaw")).isEqualTo("fixture-id-token");
        assertThat(model.get("accessTokenRaw")).isEqualTo("opaque-fixture-access-token");
        assertThat(model.get("accessTokenClaims")).isNull();
        assertThat(model.get("idTokenClaims").toString()).contains("group-one").doesNotContain("could not be formatted");
        assertThat(model.get("userInfoClaims").toString()).contains("group-two");
    }
    @Test void enabledDecodesJwtAccessTokenWithoutTreatingClaimsAsAuthority() {
        var jwt=new SignedJWT(new JWSHeader(JWSAlgorithm.ES256),new JWTClaimsSet.Builder().subject("fixture-user").claim("roles",List.of("bank-hr")).build());
        String encoded=jwt.getHeader().toBase64URL()+"."+jwt.getPayload().toBase64URL()+".AA";
        var f=fixture(encoded); var model=new ExtendedModelMap();
        new AccountAccessController(f.clients(),true,"roles").access(f.authentication(),f.request(),model);
        assertThat(model.get("accessTokenClaims").toString()).contains("bank-hr");
        assertThat(model.get("hrAccess")).isEqualTo(false);
    }
    @Test void missingAuthorizedClientStillShowsIdToken() {
        var f=fixture(null); var model=new ExtendedModelMap();
        new AccountAccessController(f.clients(),true,"roles").access(f.authentication(),f.request(),model);
        assertThat(model.get("accessTokenAvailable")).isEqualTo(false);
        assertThat(model.get("idTokenRaw")).isEqualTo("fixture-id-token");
    }
}
