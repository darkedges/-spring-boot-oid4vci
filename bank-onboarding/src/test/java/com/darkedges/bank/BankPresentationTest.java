package com.darkedges.bank;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.jdbc.core.JdbcTemplate;
import com.darkedges.oid4vci.issuer.*;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vp.sdjwt.KbJwtBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.file.*;
import java.time.*;
import java.util.*;
class BankPresentationTest {
 @TempDir Path dir;
 JdbcTemplate db; BankController bank; ECKey issuer,holder; UUID hire;
 @BeforeEach void setup() throws Exception {
  db=mock(JdbcTemplate.class); issuer=new ECKeyGenerator(Curve.P_256).generate(); holder=new ECKeyGenerator(Curve.P_256).generate();
  Path file=dir.resolve("trusted.jwk"); Files.writeString(file,issuer.toPublicJWK().toJSONString());
  bank=new BankController(db,mock(PreAuthorizedCodeStore.class),issuer,"http://bank","http://passport",file.toString(),"Example Bank"); hire=UUID.randomUUID();
  when(db.queryForMap(anyString(),eq("transaction"))).thenReturn(Map.of("nonce","expected","hire_id",hire,"complete",false));
  when(db.update(startsWith("update bank_hire"),any(),any(),any(),any(),any())).thenReturn(1);
 }
 String presentation(ECKey signer,String nonce) throws Exception { return presentation(signer,nonce,false); }
 String presentation(ECKey signer,String nonce,boolean unproofed) throws Exception {
  var config=new SdJwtVcCredentialConfiguration("http://passport/vct/PassportCredential",List.of(),Map.of(),List.of(),List.of(),Optional.empty());
  String credential=new SdJwtVcCredentialIssuanceService(signer,List.of(),Duration.ofDays(1),Clock.systemUTC()).issue(config,Map.of("given_name","Jane","family_name","Smith","birth_date","1990-01-01","assurance_level","poc-demo","expiry_date","2099-01-01","evidence",(unproofed ? "liveness=not-passed" : "liveness=passed; face-match=passed; chip-signature=verified; csca-chain=verified; portrait-from-chip=verified")),holder.toPublicJWK(),"http://passport");
  String kb=KbJwtBuilder.build(credential,nonce,"redirect_uri:http://bank/vp/response/transaction",Instant.now(),JWSAlgorithm.ES256,new ECDSASigner(holder)).serialize();
  return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("passport",List.of(credential+kb)));
 }
 @Test void onlyCanonicalStaffCredentialCanSignIn() throws Exception {
  var tx=new HashMap<String,Object>();tx.put("nonce","expected");tx.put("complete",false);tx.put("hire_id",null);
  when(db.queryForMap(anyString(),eq("transaction"))).thenReturn(tx);
  UUID staff=UUID.randomUUID();
  var config=new SdJwtVcCredentialConfiguration("http://bank/vct/BankStaffCredential",List.of(),Map.of(),List.of(),List.of(),Optional.empty());
  var service=new SdJwtVcCredentialIssuanceService(issuer,List.of(),Duration.ofDays(1),Clock.systemUTC());
  String current=service.issue(config,Map.of("staff_id",staff.toString(),"bank_id","http://bank"),holder.toPublicJWK(),"http://bank");
  String older=service.issue(config,Map.of("staff_id",staff.toString(),"bank_id","http://bank"),holder.toPublicJWK(),"http://bank");
  when(db.queryForObject(anyString(),eq(Integer.class),eq(staff))).thenReturn(1);
  when(db.queryForMap("select issued_credential from bank_hire where id=?",staff)).thenReturn(Map.of("issued_credential",current));
  for(String credential:List.of(older,current)) {
   String kb=KbJwtBuilder.build(credential,"expected","redirect_uri:http://bank/vp/response/transaction",Instant.now(),JWSAlgorithm.ES256,new ECDSASigner(holder)).serialize();
   String vp=new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("staff",List.of(credential+kb)));
   if(credential.equals(current)) assertThat(bank.response("transaction","transaction",vp)).isEqualTo("{}");
   else assertThatThrownBy(()->bank.response("transaction","transaction",vp)).hasMessageContaining("superseded");
  }
  verify(db,atLeastOnce()).queryForObject(contains("not exists"),eq(Integer.class),eq(staff));
 }
 @Test void acceptsTrustedHolderBoundIdentity() throws Exception { assertThat(bank.response("transaction","transaction",presentation(issuer,"expected"))).isEqualTo("{}"); }
 @Test void rejectsTrustedCredentialWithoutPassingProofing() throws Exception {
  String credential=presentation(issuer,"expected",true);
  assertThatThrownBy(()->bank.response("transaction","transaction",credential)).isInstanceOf(RuntimeException.class);
  verify(db,never()).update(startsWith("update bank_hire"),any(),any(),any(),any(),any());
 }
 @Test void rejectsUntrustedSigningKey() throws Exception {
  String forged=presentation(new ECKeyGenerator(Curve.P_256).generate(),"expected");
  assertThatThrownBy(()->bank.response("transaction","transaction",forged)).isInstanceOf(RuntimeException.class);
  verify(db,never()).update(startsWith("update bank_hire"),any(),any(),any(),any(),any());
 }
 @Test void rejectsWrongNonce() throws Exception {
  String replay=presentation(issuer,"other");
  assertThatThrownBy(()->bank.response("transaction","transaction",replay)).isInstanceOf(RuntimeException.class);
 }
 @Test void rejectsCompletedTransaction() throws Exception {
  when(db.queryForMap(anyString(),eq("transaction"))).thenReturn(Map.of("nonce","expected","hire_id",hire,"complete",true));
  String replay=presentation(issuer,"expected");
  assertThatThrownBy(()->bank.response("transaction","transaction",replay)).isInstanceOf(RuntimeException.class);
 }
}
