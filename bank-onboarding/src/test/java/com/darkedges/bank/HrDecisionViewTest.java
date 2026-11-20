package com.darkedges.bank;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;

class HrDecisionViewTest {
    private String render(String status) { return render(status,null); }
    private String render(String status, UUID next) {
        var servlet=new MockServletContext();
        var request=new MockHttpServletRequest(servlet,"GET","/hr");
        var response=new MockHttpServletResponse();
        var exchange=JakartaServletWebApplication.buildApplication(servlet).buildExchange(request,response);
        var row=new HashMap<String,Object>();
        for (String field : List.of("verified_given","verified_family","verified_birth","decision_reason","revocation_reason","previous_hire_id","next_hire_id")) row.put(field,null);
        row.put("next_hire_id",next);
        row.put("id",UUID.randomUUID()); row.put("status",status); row.put("mismatch",false);
        row.put("email","hire@example.com"); row.put("expected_given","Jane"); row.put("expected_family","Smith"); row.put("birth_date","1990-01-01");
        var resolver=new ClassLoaderTemplateResolver(); resolver.setPrefix("templates/"); resolver.setSuffix(".html");
        var engine=new SpringTemplateEngine(); engine.setTemplateResolver(resolver);
        return engine.process("hr",new WebContext(exchange,Locale.ENGLISH,Map.of("bankName","Example Bank","hires",List.of(row),"showLogout",true)));
    }
    @Test void closedStatesOfferReactivation() {
        for(String status:List.of("INACTIVE","CANCELLED","REJECTED")) {
            assertThat(render(status)).contains("Start reactivation", "forcePassportCheck", "new identity presentation");
        }
    }
    @Test void offersPostLogoutOnHrPage() {
        assertThat(render("REVIEW")).contains("action=\"/logout\"", "method=\"post\"", "Log out");
    }
    @Test void providesLiveStatusAndApprovalNotificationHooks() {
        assertThat(render("APPROVED")).contains("id=\"hire-list\"", "data-status=\"APPROVED\"", "id=\"watch-notifications\"", "aria-live=\"polite\"", "/hr-watch.js");
    }
    @Test void approvedHireOffersRevocationAndNoInvalidDecisionButtons() {
        assertThat(render("APPROVED")).contains("collect the staff credential", "value=\"revoke\"", "Revoke approval", "Reason for revocation")
                .doesNotContain("value=\"approve\"","value=\"reject\"","value=\"cancel\"","value=\"deactivate\"","Replace invitation");
    }
    @Test void revokedHireOffersFreshVerificationWithoutApprovalOrDeactivation() {
        assertThat(render("REVOKED")).contains("Approval revoked", "Start reactivation", "/reverify")
                .doesNotContain("value=\"revoke\"", "value=\"approve\"", "value=\"deactivate\"");
    }
    @Test void existingFollowupHasNavigationInsteadOfAnotherRequestButton() {
        UUID next=UUID.randomUUID();
        assertThat(render("REVOKED",next)).contains("View reissued verification request","#hire-"+next)
                .doesNotContain("Start reactivation");
    }
    @Test void reviewOffersApprovalAndActiveStaffOffersOnlyDeactivation() {
        assertThat(render("REVIEW")).contains("value=\"approve\"","value=\"reject\"","value=\"cancel\"").doesNotContain("value=\"deactivate\"");
        assertThat(render("ACTIVE")).contains("value=\"deactivate\"").doesNotContain("value=\"approve\"","value=\"reject\"","value=\"cancel\"");
    }
}
