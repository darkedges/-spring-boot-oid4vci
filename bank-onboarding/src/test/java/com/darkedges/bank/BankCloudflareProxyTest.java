package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.web.RequestBaseUrl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.filter.ForwardedHeaderFilter;
import static org.assertj.core.api.Assertions.assertThat;

class BankCloudflareProxyTest {
    @Test void tunnelHeadersProduceCanonicalIssuerAndHttpsRedirects() throws Exception {
        var request=new MockHttpServletRequest("GET","/hr");
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8094);
        request.addHeader("X-Forwarded-Proto","https");
        request.addHeader("X-Forwarded-Host","hr.bank.darkedges.com");
        request.addHeader("X-Forwarded-Port","443");
        var response=new MockHttpServletResponse();
        new ForwardedHeaderFilter().doFilter(request,response,(req,res)-> {
            var forwarded=(HttpServletRequest)req;
            assertThat(forwarded.isSecure()).isTrue();
            assertThat(RequestBaseUrl.resolve(forwarded)).isEqualTo("https://hr.bank.darkedges.com");
            ((HttpServletResponse)res).sendRedirect("/oauth2/authorization/hr");
        });
        assertThat(response.getRedirectedUrl()).isEqualTo("https://hr.bank.darkedges.com/oauth2/authorization/hr");
    }
}
