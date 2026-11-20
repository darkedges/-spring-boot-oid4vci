package com.darkedges.bank;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.time.temporal.TemporalAccessor;
import java.util.*;

@Controller
class AccountAccessController {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final OAuth2AuthorizedClientRepository clients;
    private final boolean tokenDebugEnabled;
    private final String hrClaim;

    AccountAccessController(OAuth2AuthorizedClientRepository clients,
            @Value("${bank.token-debug-enabled:false}") boolean tokenDebugEnabled,
            @Value("${bank.hr-claim:roles}") String hrClaim) {
        this.clients = clients;
        this.tokenDebugEnabled = tokenDebugEnabled;
        this.hrClaim = hrClaim;
    }

    @GetMapping({"/account/access", "/account/access/"})
    String access(Authentication authentication, HttpServletRequest request, Model model) {
        OidcUser user = authentication.getPrincipal() instanceof OidcUser oidc ? oidc : null;
        Object roles = user == null ? null : user.getClaims().get(hrClaim);
        boolean array = roles instanceof Collection<?>;
        boolean scalarGroup = "groups".equals(hrClaim) && roles instanceof String;
        model.addAttribute("hrClaim", hrClaim);
        model.addAttribute("rolesPresent", roles != null);
        model.addAttribute("rolesArray", array || scalarGroup);
        model.addAttribute("roles", array ? (Collection<?>) roles : scalarGroup ? List.of(roles) : List.of());
        model.addAttribute("hrAccess", authentication.getAuthorities().stream().anyMatch(a -> "BANK_HR".equals(a.getAuthority())));
        model.addAttribute("tokenDebugEnabled", tokenDebugEnabled && user != null);
        if (tokenDebugEnabled && user != null) {
            model.addAttribute("idTokenRaw", user.getIdToken().getTokenValue());
            model.addAttribute("idTokenClaims", pretty(user.getIdToken().getClaims()));
            model.addAttribute("userInfoClaims", user.getUserInfo() == null ? null : pretty(user.getUserInfo().getClaims()));
            OAuth2AuthorizedClient client = authentication instanceof OAuth2AuthenticationToken oauth
                    ? clients.loadAuthorizedClient(oauth.getAuthorizedClientRegistrationId(), authentication, request) : null;
            model.addAttribute("accessTokenAvailable", client != null && client.getAccessToken() != null);
            if (client != null && client.getAccessToken() != null) {
                var accessToken = client.getAccessToken();
                model.addAttribute("accessTokenRaw", accessToken.getTokenValue());
                model.addAttribute("accessTokenScopes", accessToken.getScopes());
                model.addAttribute("accessTokenExpiresAt", accessToken.getExpiresAt());
                try {
                    var jwt = JWTParser.parse(accessToken.getTokenValue());
                    model.addAttribute("accessTokenHeader", pretty(jwt.getHeader().toJSONObject()));
                    model.addAttribute("accessTokenClaims", pretty(jwt.getJWTClaimsSet().getClaims()));
                } catch (Exception ignored) {
                    // Opaque/encrypted tokens cannot be decoded here. Parser messages may
                    // contain the raw token and must never be logged or displayed.
                    model.addAttribute("accessTokenClaims", null);
                }
            }
        }
        return "account-access";
    }
    private static String pretty(Object value) {
        try { return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(jsonValue(value)); }
        catch (Exception ignored) { return "Claims could not be formatted."; }
    }
    private static Object jsonValue(Object value) {
        if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean) return value;
        if (value instanceof Date date) return date.toInstant().toString();
        if (value instanceof TemporalAccessor temporal) return temporal.toString();
        if (value instanceof Map<?, ?> map) {
            Map<String,Object> result = new LinkedHashMap<>();
            map.forEach((key, item) -> result.put(String.valueOf(key), jsonValue(item)));
            return result;
        }
        if (value instanceof Collection<?> list) return list.stream().map(AccountAccessController::jsonValue).toList();
        return value.toString();
    }
}
