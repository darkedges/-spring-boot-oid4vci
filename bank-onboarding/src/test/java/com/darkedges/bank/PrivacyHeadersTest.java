package com.darkedges.bank;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.assertThat;

class PrivacyHeadersTest {
    @Test
    void registersWithoutBeanOverridingAndAppliesHeaders() throws Exception {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.getDefaultListableBeanFactory().setAllowBeanDefinitionOverriding(false);
            context.register(PrivacyHeaders.class);
            context.refresh();

            assertThat(context.getBean("privacyHeaders")).isInstanceOf(PrivacyHeaders.class);
            var registration = context.getBean("privacyHeadersFilter", FilterRegistrationBean.class);
            var request = new MockHttpServletRequest("GET", "/hr");
            var response = new MockHttpServletResponse();
            var continued = new AtomicBoolean();
            registration.getFilter().doFilter(request, response, (req, res) -> continued.set(true));

            assertThat(continued.get()).isTrue();
            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
            assertThat(response.getHeader("Referrer-Policy")).isEqualTo("no-referrer");
        }
    }
}
