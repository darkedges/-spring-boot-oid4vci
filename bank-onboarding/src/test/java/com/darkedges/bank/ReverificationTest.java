package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.server.ResponseStatusException;
import java.nio.file.*;
import java.sql.Date;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ReverificationTest {
    @TempDir Path dir;
    JdbcTemplate db; BankController bank; UUID previous;
    @BeforeEach void setup() throws Exception {
        db=mock(JdbcTemplate.class); previous=UUID.randomUUID();
        var key=new ECKeyGenerator(Curve.P_256).generate();
        Path file=dir.resolve("public.jwk"); Files.writeString(file,key.toPublicJWK().toJSONString());
        bank=new BankController(db,mock(PreAuthorizedCodeStore.class),key,"https://hr.bank.darkedges.com","https://issuer.example",file.toString(),"Example Bank");
    }
    Map<String,Object> old(String status) {
        return new HashMap<>(Map.of("status",status,"expected_given","Jane","expected_family","Smith","birth_date",Date.valueOf("1990-01-01"),"email","fixture@example.com","department","Finance"));
    }
    @Test void freshRequestCopiesOnlyExpectedIdentityAndLeavesRevokedAttemptClosed() {
        when(db.queryForMap(anyString(),eq(previous))).thenReturn(old("REVOKED"));
        when(db.queryForList(anyString(),eq(previous))).thenReturn(List.of());
        var mail=mock(InvitationEmailService.class); bank.setInvitationEmail(mail);
        var model=new ExtendedModelMap();
        assertThat(bank.reverify(previous,model,()->"hr")).isEqualTo("invitation");
        var next=ArgumentCaptor.forClass(UUID.class);
        var invitationHash=ArgumentCaptor.forClass(String.class);
        verify(db).update(eq("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,invite_hash,invite_expires,previous_hire_id) values (?,?,?,?,?,?,?,?,?)"),
                next.capture(),eq("Jane"),eq("Smith"),eq(Date.valueOf("1990-01-01")),eq("fixture@example.com"),eq("Finance"),invitationHash.capture(),any(java.sql.Timestamp.class),eq(previous));
        assertThat(next.getValue()).isNotEqualTo(previous);
        String link=model.get("invite").toString();
        assertThat(link).startsWith("https://hr.bank.darkedges.com/invite/");
        verify(mail).deliver(eq("fixture@example.com"),eq(link),same(model));
        String token=link.substring(link.lastIndexOf('/')+1);
        assertThat(invitationHash.getValue()).isEqualTo(BankController.hash(token));
        verify(db).update(eq("insert into bank_audit(hire_id,action,actor) values (?,?,?)"),eq(previous),eq("VERIFICATION_REQUEST_REISSUED"),eq("hr"));
        verify(db).update(eq("insert into bank_audit(hire_id,action,actor) values (?,?,?)"),eq(next.getValue()),eq("VERIFICATION_REQUESTED"),eq("hr"));
        verify(db,never()).update(startsWith("update bank_hire"),any(Object[].class));
    }
    @Test void forcedRequestPersistsFreshProofingRequirement() {
        when(db.queryForMap(anyString(),eq(previous))).thenReturn(old("REVOKED"));
        when(db.queryForList(anyString(),eq(previous))).thenReturn(List.of());
        bank.reverify(previous,true,new ExtendedModelMap(),()->"hr");
        verify(db).update(eq("update bank_hire set passport_check_after=? where id=?"),any(java.sql.Timestamp.class),any(UUID.class));
        verify(db).update(eq("insert into bank_audit(hire_id,action,actor) values (?,?,?)"),any(UUID.class),eq("FRESH_PASSPORT_CHECK_REQUIRED"),eq("hr"));
    }
    @Test void signedProofingTimeMustMeetCutoff() {
        var json=new com.fasterxml.jackson.databind.ObjectMapper(); var cutoff=java.time.Instant.now().minusSeconds(60);
        assertThat(BankController.freshPassport(json.valueToTree(Map.of()),cutoff)).isFalse();
        assertThat(BankController.freshPassport(json.valueToTree(Map.of("proofed_at",cutoff.minusSeconds(1).toString())),cutoff)).isFalse();
        assertThat(BankController.freshPassport(json.valueToTree(Map.of("proofed_at",cutoff.plusSeconds(1).toString())),cutoff)).isTrue();
        assertThat(BankController.freshPassport(json.valueToTree(Map.of("proofed_at",cutoff.plusSeconds(9999).toString())),cutoff)).isFalse();
        assertThat(BankController.freshPassport(json.valueToTree(Map.of()),null)).isTrue();
    }
    @Test void repeatedSubmissionReturnsExistingRequestWithoutRotatingItsInvitation() {
        UUID next=UUID.randomUUID();
        when(db.queryForMap(anyString(),eq(previous))).thenReturn(old("REVOKED"));
        when(db.queryForList(anyString(),eq(previous))).thenReturn(List.of(Map.of("id",next)));
        assertThat(bank.reverify(previous,new ExtendedModelMap(),()->"hr")).isEqualTo("redirect:/hr#hire-"+next);
        verify(db).queryForMap(anyString(),eq(previous)); verify(db).queryForList(anyString(),eq(previous)); verifyNoMoreInteractions(db);
    }
    @Test void creatingAndReplacingInvitationsUseTheRecordedEmail() {
        var mail=mock(InvitationEmailService.class); bank.setInvitationEmail(mail);
        var created=new ExtendedModelMap();
        bank.create("Jane","Smith",java.time.LocalDate.of(1990,1,1)," newhire@example.com ","Finance",created,()->"hr");
        verify(mail).deliver(eq("newhire@example.com"),eq(created.get("invite").toString()),same(created));
        when(db.update(startsWith("update bank_hire set invite_hash"),any(),any(),eq(previous))).thenReturn(1);
        when(db.queryForMap("select email from bank_hire where id=?",previous)).thenReturn(Map.of("email","recorded@example.com"));
        var replaced=new ExtendedModelMap();
        bank.invite(previous,replaced,()->"hr");
        verify(mail).deliver(eq("recorded@example.com"),eq(replaced.get("invite").toString()),same(replaced));
    }
    @Test void requiresRevokedState() {
        for(String status:List.of("INVITED","REVIEW","APPROVED","ACTIVE")) {
            when(db.queryForMap(anyString(),eq(previous))).thenReturn(old(status));
            assertThatThrownBy(()->bank.reverify(previous,new ExtendedModelMap(),()->"hr")).isInstanceOf(ResponseStatusException.class);
        }
        verify(db,never()).update(anyString(),any(Object[].class));
    }
    @Test void closedAttemptsCanStartReactivationWithoutRestoringOldAccess() {
        for(String status:List.of("INACTIVE","CANCELLED","REJECTED")) {
            when(db.queryForMap(anyString(),eq(previous))).thenReturn(old(status));
            when(db.queryForList(anyString(),eq(previous))).thenReturn(List.of());
            assertThat(bank.reverify(previous,new ExtendedModelMap(),()->"hr")).isEqualTo("invitation");
        }
        verify(db,never()).update(startsWith("update bank_hire set status='ACTIVE'"),any(Object[].class));
    }
    @Test void newAttemptStillNeedsPresentationBeforeApproval() {
        UUID next=UUID.randomUUID();
        when(db.queryForMap(anyString(),eq(next))).thenReturn(old("INVITED"));
        assertThatThrownBy(()->bank.decision(next,"approve","",()->"hr")).isInstanceOf(ResponseStatusException.class);
        verify(db,never()).update(anyString(),any(Object[].class));
    }
}
