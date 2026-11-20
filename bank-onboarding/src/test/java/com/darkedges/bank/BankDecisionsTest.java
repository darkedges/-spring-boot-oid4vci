package com.darkedges.bank;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.Curve;
import java.nio.file.*;
import java.util.*;
import java.sql.Date;
class BankDecisionsTest {
 @TempDir Path dir;
 JdbcTemplate db; BankController bank; UUID id;
 @BeforeEach void setup() throws Exception {
  db=mock(JdbcTemplate.class); var key=new ECKeyGenerator(Curve.P_256).generate();
  Path file=dir.resolve("public.jwk"); Files.writeString(file,key.toPublicJWK().toJSONString());
  bank=new BankController(db,mock(PreAuthorizedCodeStore.class),key,"http://bank","http://passport",file.toString(),"Example Bank"); id=UUID.randomUUID();
 }
 Map<String,Object> hire(String status) { return new HashMap<>(Map.of("status",status,"expected_given","Jane","expected_family","Smith","verified_given","JANE","verified_family","SMITH","birth_date",Date.valueOf("1990-01-01"),"verified_birth",Date.valueOf("1990-01-01"))); }
 @Test void cannotApproveBeforeProofing() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("INVITED"));
  assertThatThrownBy(()->bank.decision(id,"approve","",()->"hr")).isInstanceOf(ResponseStatusException.class);
 }
 @Test void mismatchRequiresExplanation() {
  var row=hire("REVIEW"); row.put("verified_family","Other"); when(db.queryForMap(anyString(),eq(id))).thenReturn(row);
  assertThatThrownBy(()->bank.decision(id,"approve","",()->"hr")).isInstanceOf(ResponseStatusException.class);
  assertThat(bank.decision(id,"approve","Recruitment record checked",()->"hr")).isEqualTo("redirect:/hr");
 }
 @Test void repeatedApprovalDoesNotOverwriteTheFirstDecision() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("APPROVED"));
  assertThat(bank.decision(id,"approve","changed reason",()->"other-hr")).isEqualTo("redirect:/hr");
  verify(db,never()).update(anyString(),any(Object[].class));
 }
 @Test void inactiveStaffCannotAccessPortal() {
  when(db.queryForObject(anyString(),eq(Integer.class),eq(id))).thenReturn(0);
  assertThatThrownBy(()->bank.active(id)).isInstanceOf(ResponseStatusException.class);
 }
 @Test void cancelledHireCannotBeApproved() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("CANCELLED"));
  assertThatThrownBy(()->bank.decision(id,"approve","",()->"hr")).isInstanceOf(ResponseStatusException.class);
 }
 @Test void revokeApprovalRecordsReasonAndPreservesOriginalReview() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("APPROVED"));
  assertThat(bank.decision(id,"revoke","  Offer withdrawn  ",()->"hr")).isEqualTo("redirect:/hr");
  verify(db).update(eq("update bank_hire set status='REVOKED',revocation_reason=?,revoked_by=?,revoked_at=now() where id=?"),eq("Offer withdrawn"),eq("hr"),eq(id));
  verify(db).update(eq("insert into bank_audit(hire_id,action,actor,reason) values (?,'APPROVAL_REVOKED',?,?)"),eq(id),eq("hr"),eq("Offer withdrawn"));
 }
 @Test void revocationRequiresReason() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("APPROVED"));
  assertThatThrownBy(()->bank.decision(id,"revoke"," ",()->"hr")).isInstanceOf(ResponseStatusException.class).hasMessageContaining("reason");
  verify(db).queryForMap(anyString(),eq(id)); verifyNoMoreInteractions(db);
 }
 @Test void repeatedRevocationDoesNotOverwriteItsFirstReason() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("REVOKED"));
  assertThat(bank.decision(id,"revoke","different reason",()->"other-hr")).isEqualTo("redirect:/hr");
  verify(db).queryForMap(anyString(),eq(id)); verifyNoMoreInteractions(db);
 }
 @Test void cannotRevokeAnUnapprovedHire() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("INVITED"));
  assertThatThrownBy(()->bank.decision(id,"revoke","Withdraw",()->"hr")).isInstanceOf(ResponseStatusException.class);
  verify(db).queryForMap(anyString(),eq(id)); verifyNoMoreInteractions(db);
 }
 @Test void revocationAlsoBlocksStaffIfIssuanceWonTheRace() {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("ACTIVE"));
  assertThat(bank.decision(id,"revoke","Withdraw",()->"hr")).isEqualTo("redirect:/hr");
  verify(db).update(eq("update bank_hire set status='REVOKED',revocation_reason=?,revoked_by=?,revoked_at=now() where id=?"),eq("Withdraw"),eq("hr"),eq(id));
 }
 @Test void revokedApprovalCannotCollectAnOfferOrBeApprovedAgain() throws Exception {
  when(db.queryForMap(anyString(),eq(id))).thenReturn(hire("REVOKED"));
  var session=new org.springframework.mock.web.MockHttpSession(); session.setAttribute("hire",id.toString());
  assertThatThrownBy(()->bank.offer(session,new org.springframework.ui.ExtendedModelMap())).isInstanceOf(ResponseStatusException.class);
  assertThatThrownBy(()->bank.decision(id,"approve","",()->"hr")).isInstanceOf(ResponseStatusException.class);
 }

}
