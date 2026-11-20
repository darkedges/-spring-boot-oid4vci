package com.darkedges.bank;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Staff sign-in through AuthStack (registration "staff", Spring profile authstack-staff). The sign-in itself is Authr's bank-staff-signin flow:
 * the wallet presents the staff credential to this bank, the bank names the staff member (Journey API consume), and AuthStack issues an ID token
 * whose email is staff-&lt;staff id&gt;@&lt;bank.staff-email-domain&gt;. Here that staff id is read back and checked against this database (active, and
 * not superseded by a newer attempt) before the browser gets a staff session, exactly the session /vp/result gives a portal sign-in; /staff
 * checks it again on every request. The AuthStack sign-in itself is not kept: it is not an HR login and grants nothing else.
 */
@Component
public class StaffSignIn {
    static final String REGISTRATION = "staff";
    private final JdbcTemplate db;
    private final Pattern email;

    public StaffSignIn(JdbcTemplate db, @Value("${bank.staff-email-domain:staff.bank.darkedges.com}") String domain) {
        this.db = db;
        this.email = Pattern.compile("^staff-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})@" + Pattern.quote(domain.toLowerCase(Locale.ROOT)) + "$");
    }

    /** The staff id an AuthStack staff identity stands for, if the address is one. */
    Optional<UUID> staffIdFrom(String address) {
        if (address == null) return Optional.empty();
        var match = email.matcher(address.trim().toLowerCase(Locale.ROOT));
        return match.matches() ? Optional.of(UUID.fromString(match.group(1))) : Optional.empty();
    }

    boolean active(UUID id) {
        return db.queryForObject("select count(*) from bank_hire h where h.id=? and h.status='ACTIVE' and not exists (select 1 from bank_hire newer where newer.previous_hire_id=h.id)", Integer.class, id) == 1;
    }

    /** After any OIDC sign-in: an HR sign-in carries on as before; a staff sign-in becomes a staff session, or is refused. */
    AuthenticationSuccessHandler successHandler() {
        var hr = new SavedRequestAwareAuthenticationSuccessHandler();
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            if (!(authentication instanceof OAuth2AuthenticationToken token) || !REGISTRATION.equals(token.getAuthorizedClientRegistrationId())) {
                hr.onAuthenticationSuccess(request, response, authentication);
                return;
            }
            // Not kept as a signed-in principal: the staff session below is the only thing this sign-in gives.
            SecurityContextHolder.clearContext();
            new HttpSessionSecurityContextRepository().saveContext(SecurityContextHolder.createEmptyContext(), request, response);
            var staff = token.getPrincipal() instanceof OidcUser user ? staffIdFrom(user.getEmail()) : Optional.<UUID>empty();
            if (staff.isEmpty() || !active(staff.get())) {
                response.sendRedirect("/?staff=refused");
                return;
            }
            request.changeSessionId();
            request.getSession().setAttribute("staff", staff.get().toString());
            response.sendRedirect("/staff");
        };
    }
}
