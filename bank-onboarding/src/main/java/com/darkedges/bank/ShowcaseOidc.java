package com.darkedges.bank;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.*;
/** Separate local demo provider; no discovery call to browser-localhost from Docker. */
@Configuration @Profile("showcase")
class ShowcaseOidc {
 @Bean ClientRegistrationRepository showcaseClients() {
  String browser="http://localhost:43180/realms/risk-e-demo", internal="http://idp:8080/realms/risk-e-demo/protocol/openid-connect";
  return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("hr").clientId("risk-e-hr").clientSecret("showcase-client-only")
   .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost:43194/login/oauth2/code/hr").scope("openid","profile")
   .authorizationUri(browser+"/protocol/openid-connect/auth").tokenUri(internal+"/token").jwkSetUri(internal+"/certs").userInfoUri(internal+"/userinfo").userNameAttributeName("sub").issuerUri(browser).clientName("Risk E Bank Demo HR").build());
 }
}
