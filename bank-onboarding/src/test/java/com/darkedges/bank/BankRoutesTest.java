package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceView;
import java.nio.file.*;
import java.util.List;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class BankRoutesTest {
    @TempDir Path dir;
    @Test void hrReturnUrlAcceptsTrailingSlashAndContinueParameter() throws Exception {
        var key=new ECKeyGenerator(Curve.P_256).generate();
        Path publicKey=dir.resolve("issuer.jwk");
        Files.writeString(publicKey,key.toPublicJWK().toJSONString());
        var db=mock(JdbcTemplate.class);
        when(db.queryForList(anyString())).thenReturn(List.of());
        var controller=new BankController(db,mock(PreAuthorizedCodeStore.class),key,
                "http://localhost:8094","https://issuer.example",publicKey.toString(),"Example Bank");
        var mvc=MockMvcBuilders.standaloneSetup(controller)
                .setSingleView(new InternalResourceView("/WEB-INF/route-test.jsp")).build();
        mvc.perform(get("/")).andExpect(model().attribute("showLogout",false));
        var emptySession=new org.springframework.mock.web.MockHttpSession();
        mvc.perform(get("/").session(emptySession)).andExpect(model().attribute("showLogout",false));
        for(String sessionKey:List.of("staff","hire")) {
            var session=new org.springframework.mock.web.MockHttpSession();session.setAttribute(sessionKey,java.util.UUID.randomUUID().toString());
            mvc.perform(get("/").session(session)).andExpect(model().attribute("showLogout",true));
        }
        mvc.perform(get("/").principal(()->"hr-user")).andExpect(model().attribute("showLogout",true));
        for(String path:List.of("/hr","/hr/")) {
            mvc.perform(get(path).queryParam("continue",""))
                    .andExpect(status().isOk())
                    .andExpect(handler().methodName("hires"))
                    .andExpect(view().name("hr"))
                    .andExpect(model().attribute("hires",List.of()));
        }
        var historical=new java.util.HashMap<String,Object>(); historical.put("id",java.util.UUID.randomUUID());historical.put("next_hire_id",java.util.UUID.randomUUID());
        var current=new java.util.HashMap<String,Object>();current.put("id",historical.get("next_hire_id"));current.put("next_hire_id",null);
        when(db.queryForList(anyString())).thenReturn(List.of(current,historical));
        mvc.perform(get("/hr")).andExpect(model().attribute("hires",List.of(current)))
                .andExpect(model().attribute("hireHistory",List.of(historical)));
    }
}
