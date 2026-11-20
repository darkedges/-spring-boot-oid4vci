package com.darkedges.bank;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
class PresentationStatusTest {
 @TempDir Path dir;
 JdbcTemplate db; BankController bank; MockHttpSession session;
 @BeforeEach void setup() throws Exception {
  db=mock(JdbcTemplate.class);var key=new ECKeyGenerator(Curve.P_256).generate();var file=dir.resolve("public.jwk");Files.writeString(file,key.toPublicJWK().toJSONString());
  bank=new BankController(db,mock(PreAuthorizedCodeStore.class),key,"https://hr.bank.darkedges.com","https://issuer.example",file.toString(),"Bank");
  session=new MockHttpSession();session.setAttribute("vp:request","secret");
 }
 void outcome(boolean complete,Instant expiry) {
  when(db.queryForList(anyString(),eq("request"))).thenReturn(List.of(Map.of("complete",complete,"expires_at",java.sql.Timestamp.from(expiry),"browser_secret_hash",BankController.hash("secret"))));
 }
 @Test void reportsPendingAndCompleteWithoutConsumingBrowserProofOrSigningIn() {
  for(boolean complete:List.of(false,true)) {
   outcome(complete,Instant.now().plusSeconds(600));
   assertThat(bank.presentationStatus("request",session)).contains(complete?"complete":"pending");
   assertThat(session.getAttribute("vp:request")).isEqualTo("secret");assertThat(session.getAttribute("staff")).isNull();
  }
  verify(db,never()).update(anyString(),any(Object[].class));
 }
 @Test void expiresEvenAfterCompletion() {
  outcome(true,Instant.now().minusSeconds(1));assertThat(bank.presentationStatus("request",session)).contains("expired");
 }
 @Test void rejectsOtherBrowserAndIncorrectSecret() {
  assertThatThrownBy(()->bank.presentationStatus("request",new MockHttpSession())).isInstanceOf(org.springframework.web.server.ResponseStatusException.class);
  outcome(true,Instant.now().plusSeconds(600));session.setAttribute("vp:request","wrong");
  assertThatThrownBy(()->bank.presentationStatus("request",session)).isInstanceOf(org.springframework.web.server.ResponseStatusException.class);
 }
}
