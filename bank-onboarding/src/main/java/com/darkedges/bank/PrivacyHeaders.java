package com.darkedges.bank;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
@Configuration
class PrivacyHeaders {
 @Bean FilterRegistrationBean<OncePerRequestFilter> privacyHeadersFilter() {
  return new FilterRegistrationBean<>(new OncePerRequestFilter() {
   protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
    res.setHeader("Cache-Control","no-store"); res.setHeader("Referrer-Policy","no-referrer");
    chain.doFilter(req,res);
   }
  });
 }
}
