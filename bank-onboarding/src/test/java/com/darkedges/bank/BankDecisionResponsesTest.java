package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceView;
import java.nio.file.*;
import java.util.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class BankDecisionResponsesTest {
    @TempDir Path dir;
    JdbcTemplate db;
    MockMvc mvc;
    UUID id;
    @BeforeEach void setup() throws Exception {
        id=UUID.randomUUID(); db=mock(JdbcTemplate.class);
        var key=new ECKeyGenerator(Curve.P_256).generate();
        Path file=dir.resolve("public.jwk"); Files.writeString(file,key.toPublicJWK().toJSONString());
        var bank=new BankController(db,mock(PreAuthorizedCodeStore.class),key,"http://bank","http://passport",file.toString(),"Example Bank");
        mvc=MockMvcBuilders.standaloneSetup(bank).build();
    }
    @Test void repeatedApprovalRedirectsWithoutChangingDecisionOrAudit() throws Exception {
        when(db.queryForMap(anyString(),eq(id))).thenReturn(Map.of("status","APPROVED"));
        mvc.perform(post("/hr/hires/{id}/decision",id).param("decision","approve").param("reason","replacement").principal(()->"other-hr"))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/hr"));
        verify(db).queryForMap(anyString(),eq(id)); verifyNoMoreInteractions(db);
    }
    @Test void prematureApprovalShowsUsefulMessageOnHrPage() throws Exception {
        when(db.queryForMap(anyString(),eq(id))).thenReturn(Map.of("status","INVITED"));
        mvc.perform(post("/hr/hires/{id}/decision",id).param("decision","approve").principal(()->"hr"))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/hr"))
                .andExpect(flash().attribute("decisionError","A verified identity must be reviewed first"));
        verify(db).queryForMap(anyString(),eq(id)); verifyNoMoreInteractions(db);
    }
    @Test void mismatchApprovalRequiresReasonAndShowsItAsValidation() throws Exception {
        var row=new HashMap<String,Object>();
        row.put("status","REVIEW"); row.put("expected_given","Jane"); row.put("verified_given","Jane");
        row.put("expected_family","Smith"); row.put("verified_family","Other");
        row.put("birth_date",java.sql.Date.valueOf("1990-01-01")); row.put("verified_birth",java.sql.Date.valueOf("1990-01-01"));
        when(db.queryForMap(anyString(),eq(id))).thenReturn(row);
        mvc.perform(post("/hr/hires/{id}/decision",id).param("decision","approve").principal(()->"hr"))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/hr"))
                .andExpect(flash().attribute("decisionError","A mismatch requires an explanation"));
        verify(db).queryForMap(anyString(),eq(id)); verifyNoMoreInteractions(db);
    }
}
