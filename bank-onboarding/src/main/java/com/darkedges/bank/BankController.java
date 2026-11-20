package com.darkedges.bank;

import com.darkedges.oid4vci.issuer.*;
import com.darkedges.oid4vp.core.dcql.*;
import com.darkedges.oid4vp.core.response.*;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.fasterxml.jackson.databind.*;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;

@Controller
public class BankController {
    private static final ObjectMapper JSON = new ObjectMapper();
    private InvitationEmailService invitationEmail;
    @org.springframework.beans.factory.annotation.Autowired
    void setInvitationEmail(InvitationEmailService invitationEmail) { this.invitationEmail = invitationEmail; }
    private String applicantEntry = "portal", applicantEntryUrl = "";
    @org.springframework.beans.factory.annotation.Autowired
    void setApplicantEntry(@Value("${bank.applicant-entry:portal}") String entry, @Value("${bank.applicant-entry-url:}") String url) { this.applicantEntry=entry; this.applicantEntryUrl=url; }
    /** Where an invitation link sends the applicant: this portal, or (bank.applicant-entry=authr) the Authr applicant journey. The token
     *  travels in the URL fragment there, so it never reaches a server log or a Referer header. */
    String invitationLink(String invitation) {
        if ("authr".equals(applicantEntry) && !applicantEntryUrl.isBlank()) return applicantEntryUrl + "#invite=" + invitation;
        return base + "/invite/" + invitation;
    }
    private void deliverInvitation(String email, String link, Model model) {
        model.addAttribute("invite", link);
        if (invitationEmail != null) invitationEmail.deliver(email, link, model);
    }
    private final JdbcTemplate db;
    private final PreAuthorizedCodeStore codes;
    private final String base, passportIssuer, name;
    private final ECKey passportKey, bankKey;
    public BankController(JdbcTemplate db, PreAuthorizedCodeStore codes, ECKey bankKey,
        @Value("${bank.base-url}") String base, @Value("${bank.passport-issuer}") String passportIssuer,
        @Value("${bank.passport-key-file}") String keyFile, @Value("${bank.name}") String name) throws Exception {
        this.db=db; this.codes=codes; this.base=base; this.passportIssuer=passportIssuer; this.name=name;
        passportKey=ECKey.parse(Files.readString(Path.of(keyFile))).toPublicJWK(); this.bankKey=bankKey.toPublicJWK();
    }
    static String token() { byte[] b=new byte[32]; new SecureRandom().nextBytes(b); return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    static String hash(String s) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8))); } catch(Exception e) { throw new IllegalStateException(e); } }
    static String normalize(String s) { return s.replace('<',' ').trim().replaceAll("\\s+"," ").toUpperCase(Locale.ROOT); }
    static void require(boolean ok, String message) { if(!ok) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,message); }
    @ModelAttribute("showLogout") boolean showLogout(jakarta.servlet.http.HttpServletRequest request) {
        var principal=request.getUserPrincipal();
        boolean signedIn=principal!=null && !(principal instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)
                && (!(principal instanceof org.springframework.security.core.Authentication auth) || auth.isAuthenticated());
        var session=request.getSession(false);
        return signedIn || (session!=null && (session.getAttribute("staff")!=null || session.getAttribute("hire")!=null));
    }
    private boolean staffSso;
    /** Staff can sign in through AuthStack when the "staff" registration is configured (profile authstack-staff, see StaffSignIn). */
    @org.springframework.beans.factory.annotation.Autowired
    void setClientRegistrations(org.springframework.beans.factory.ObjectProvider<org.springframework.security.oauth2.client.registration.ClientRegistrationRepository> registrations) {
        var repository = registrations.getIfAvailable();
        staffSso = repository != null && repository.findByRegistrationId(StaffSignIn.REGISTRATION) != null;
    }
    @ModelAttribute void branding(Model m) { m.addAttribute("bankName",name); m.addAttribute("mailEnabled",invitationEmail != null && invitationEmail.enabled()); m.addAttribute("staffSso",staffSso); }
    @GetMapping("/") String home() { return "home"; }
    @GetMapping({"/hr", "/hr/"}) String hires(Model m) { var rows=db.queryForList("select h.*, followup.id as next_hire_id from bank_hire h left join bank_hire followup on followup.previous_hire_id=h.id order by h.created_at desc");
        for(var h:rows) h.put("mismatch",h.get("verified_family")!=null && (!normalize((String)h.get("expected_given")).equals(normalize((String)h.get("verified_given"))) || !normalize((String)h.get("expected_family")).equals(normalize((String)h.get("verified_family"))) || !h.get("birth_date").equals(h.get("verified_birth"))));
        m.addAttribute("hires",rows.stream().filter(h -> h.get("next_hire_id")==null).toList());
        m.addAttribute("hireHistory",rows.stream().filter(h -> h.get("next_hire_id")!=null).toList()); return "hr"; }
    @PostMapping("/hr/hires") @Transactional String create(@RequestParam String given, @RequestParam String family,
        @RequestParam LocalDate birth, @RequestParam String email, @RequestParam String department, Model m, java.security.Principal actor) {
        require(!family.isBlank() && InvitationEmailService.validAddress(email.trim()) && !department.isBlank() && birth.isBefore(LocalDate.now()),"Required hire details are invalid");
        UUID id=UUID.randomUUID(); String invitation=token();
        db.update("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,invite_hash,invite_expires) values (?,?,?,?,?,?,?,?)",id,given.trim(),family.trim(),birth,email.trim(),department.trim(),hash(invitation),java.sql.Timestamp.from(Instant.now().plus(Duration.ofDays(7))));
        audit(id,"CREATED",actor.getName()); deliverInvitation(email.trim(),invitationLink(invitation),m); return "invitation";
    }
    @PostMapping("/hr/hires/{id}/invite") @Transactional String invite(@PathVariable UUID id, Model m, java.security.Principal actor) {
        String t=token(); require(db.update("update bank_hire set invite_hash=?, invite_expires=? where id=? and status in ('INVITED','REVIEW')",hash(t),java.sql.Timestamp.from(Instant.now().plus(Duration.ofDays(7))),id)==1,"Hire cannot be invited");
        audit(id,"INVITATION_REISSUED",actor.getName()); deliverInvitation((String)db.queryForMap("select email from bank_hire where id=?",id).get("email"),invitationLink(t),m); return "invitation";
    }
    @PostMapping("/hr/hires/{id}/reverify") @Transactional String reverify(@PathVariable UUID id, @RequestParam(defaultValue="false") boolean forcePassportCheck, Model model, java.security.Principal actor) {
        var previous = db.queryForMap("select * from bank_hire where id=? for update", id);
        requireDecision(Set.of("REVOKED","INACTIVE","CANCELLED","REJECTED").contains(previous.get("status")), "Only a closed hire can be requested for verification again");
        var followups = db.queryForList("select id from bank_hire where previous_hire_id=?", id);
        // Repeated submissions return to the same request and leave its invitation valid.
        if (!followups.isEmpty()) return "redirect:/hr#hire-" + followups.getFirst().get("id");
        UUID nextId = UUID.randomUUID();
        String invitation = token();
        db.update("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,invite_hash,invite_expires,previous_hire_id) values (?,?,?,?,?,?,?,?,?)",
                nextId, previous.get("expected_given"), previous.get("expected_family"), previous.get("birth_date"), previous.get("email"), previous.get("department"), hash(invitation), java.sql.Timestamp.from(Instant.now().plus(Duration.ofDays(7))), id);
        if (forcePassportCheck) {
            db.update("update bank_hire set passport_check_after=? where id=?",java.sql.Timestamp.from(Instant.now()),nextId);
            audit(nextId,"FRESH_PASSPORT_CHECK_REQUIRED",actor.getName());
        }
        audit(id, "VERIFICATION_REQUEST_REISSUED", actor.getName());
        audit(nextId, "VERIFICATION_REQUESTED", actor.getName());
        deliverInvitation((String)previous.get("email"), invitationLink(invitation), model);
        return "invitation";
    }
    String reverify(UUID id, Model model, java.security.Principal actor) { return reverify(id,false,model,actor); }
    Instant passportCheckAfter(UUID hire) {
        var rows=db.queryForList("select passport_check_after from bank_hire where id=?",hire);
        return rows.isEmpty() || rows.getFirst().get("passport_check_after")==null ? null : ((java.sql.Timestamp)rows.getFirst().get("passport_check_after")).toInstant();
    }
    static boolean freshPassport(com.fasterxml.jackson.databind.JsonNode claims, Instant cutoff) {
        if(cutoff==null) return true;
        try { var proofed=Instant.parse(claims.path("proofed_at").asText());return !proofed.isBefore(cutoff) && !proofed.isAfter(Instant.now().plusSeconds(60)); }
        catch(Exception invalid) { return false; }
    }
    @PostMapping("/hr/hires/{id}/decision") @Transactional String decision(@PathVariable UUID id,@RequestParam String decision,@RequestParam(defaultValue="") String reason,java.security.Principal actor) {
        var hire=db.queryForMap("select * from bank_hire where id=? for update",id);
        requireDecision(Set.of("approve","reject","cancel","deactivate","revoke").contains(decision),"Unknown decision");
        if ("revoke".equals(decision)) {
            if ("REVOKED".equals(hire.get("status"))) return "redirect:/hr";
            // Serialize with issuance through the hire row lock. If issuance won
            // the race, withdrawing approval also blocks the newly active staff access.
            requireDecision(Set.of("APPROVED","ACTIVE").contains(hire.get("status")), "Only an approved hire can have approval revoked");
            requireDecision(!reason.isBlank(), "Enter a reason for revoking approval");
            db.update("update bank_hire set status='REVOKED',revocation_reason=?,revoked_by=?,revoked_at=now() where id=?", reason.trim(), actor.getName(), id);
            db.update("insert into bank_audit(hire_id,action,actor,reason) values (?,'APPROVAL_REVOKED',?,?)", id, actor.getName(), reason.trim());
            return "redirect:/hr";
        }
        String completedState = switch (decision) {
            case "approve" -> "APPROVED";
            case "reject" -> "REJECTED";
            case "cancel" -> "CANCELLED";
            default -> "INACTIVE";
        };
        // A retry must not overwrite the first review or append another audit event.
        if (completedState.equals(hire.get("status")) || ("approve".equals(decision) && "ACTIVE".equals(hire.get("status")))) return "redirect:/hr";
        String next;
        if(decision.equals("approve")) {
            requireDecision("REVIEW".equals(hire.get("status")),"A verified identity must be reviewed first");
            boolean mismatch=!normalize((String)hire.get("expected_given")).equals(normalize((String)hire.get("verified_given"))) || !normalize((String)hire.get("expected_family")).equals(normalize((String)hire.get("verified_family"))) || !hire.get("birth_date").equals(hire.get("verified_birth"));
            requireDecision(!mismatch || !reason.isBlank(),"A mismatch requires an explanation"); next="APPROVED";
        } else if(decision.equals("deactivate")) { requireDecision("ACTIVE".equals(hire.get("status")),"Staff is not active"); next="INACTIVE"; }
        else { requireDecision(Set.of("INVITED","REVIEW").contains(hire.get("status")),"Hire is no longer awaiting a decision"); next=decision.equals("reject")?"REJECTED":"CANCELLED"; }
        db.update("update bank_hire set status=?, decision_reason=?, reviewer=?, reviewed_at=now() where id=?",next,reason,actor.getName(),id);
        audit(id,next,actor.getName()); return "redirect:/hr";
    }
    static final class HireDecisionException extends ResponseStatusException {
        HireDecisionException(String message) { super(HttpStatus.BAD_REQUEST, message); }
    }
    static void requireDecision(boolean valid, String message) {
        if (!valid) throw new HireDecisionException(message);
    }
    @ExceptionHandler(HireDecisionException.class)
    String decisionError(HireDecisionException error, org.springframework.web.servlet.mvc.support.RedirectAttributes redirect) {
        redirect.addFlashAttribute("decisionError", error.getReason());
        return "redirect:/hr";
    }
    @GetMapping("/invite/{token}") String claim(@PathVariable String token,HttpSession session,jakarta.servlet.http.HttpServletRequest servletRequest) {
        var rows=db.queryForList("select id from bank_hire where invite_hash=? and invite_expires>now() and status not in ('CANCELLED','REJECTED','INACTIVE','REVOKED')",hash(token));
        require(rows.size()==1,"Invitation is invalid or expired");
        // Rotation prevents an observed pre-existing session identifier from becoming the applicant session.
        servletRequest.changeSessionId(); session.setAttribute("hire",rows.getFirst().get("id").toString());
        return "redirect:/onboarding";
    }
    @GetMapping({"/onboarding", "/onboarding/"}) String progress(HttpSession session, Model m) {
        UUID id=applicant(session); var h=db.queryForMap("select * from bank_hire where id=?",id);
        m.addAttribute("hire",h); m.addAttribute("passportIssuer",passportIssuer); return "onboarding";
    }
    UUID applicant(HttpSession session) { Object id=session.getAttribute("hire"); require(id!=null,"Open your invitation first"); return UUID.fromString(id.toString()); }
    @PostMapping("/onboarding/present") String present(HttpSession session,Model m) { UUID hire=applicant(session); require(awaitingIdentity(hire),"This invitation is not awaiting identity"); return start(hire,session,m); }
    @PostMapping("/staff/login") String login(HttpSession session,Model m) { return start(null,session,m); }
    String start(UUID hire,HttpSession session,Model m) {
        var p=newPresentation(hire,"portal"); session.setAttribute("vp:"+p.id(),p.secret());
        m.addAttribute("requestUrl",p.requestUri()); m.addAttribute("walletUrl",p.walletUri()); m.addAttribute("resultUrl","/vp/result/"+p.id()); m.addAttribute("statusUrl","/vp/status/"+p.id()); m.addAttribute("qrImage",WalletQr.image(p.walletUri())); return "presentation";
    }
    /** A presentation request: the wallet fetches requestUri; only whoever holds secret (a browser session, or an Authr journey) can see its result. */
    record NewPresentation(String id, String secret, Instant expiresAt, String requestUri, String walletUri) {}
    NewPresentation newPresentation(UUID hire, String channel) {
        // The database's clock sets the expiry, as it is the one that checks it (expires_at > now()).
        String id=token(), secret=token();
        Instant expires=db.queryForObject("insert into bank_presentation(id,nonce,hire_id,browser_secret_hash,expires_at,channel) values (?,?,?,?,now() + interval '600 seconds',?) returning expires_at",java.sql.Timestamp.class,id,token(),hire,hash(secret),channel).toInstant();
        String request=base+"/vp/request/"+id;
        return new NewPresentation(id,secret,expires,request,"openid4vp://?request_uri="+java.net.URLEncoder.encode(request,java.nio.charset.StandardCharsets.UTF_8));
    }
    /** INVITED and not superseded by a newer attempt: the only state in which a Passport presentation can be started. */
    boolean awaitingIdentity(UUID hire) {
        return db.queryForObject("select count(*) from bank_hire h where h.id=? and h.status='INVITED' and not exists (select 1 from bank_hire newer where newer.previous_hire_id=h.id)",Integer.class,hire)==1;
    }
    @GetMapping(value="/vp/request/{id}",produces="application/json") @ResponseBody String request(@PathVariable String id) throws Exception {
        var tx=transaction(id); String type=tx.get("hire_id")==null?"staff":"passport";
        List<Map<String,Object>> claims=new ArrayList<>();
        for(String field: type.equals("staff")?List.of("staff_id","bank_id"):List.of("given_name","family_name","birth_date","expiry_date","assurance_level","evidence")) claims.add(Map.of("path",List.of(field)));
        Instant cutoff=type.equals("passport")?passportCheckAfter((UUID)tx.get("hire_id")):null;
        if(cutoff!=null) claims.add(Map.of("path",List.of("proofed_at")));
        var body=new LinkedHashMap<String,Object>(Map.of("expires_at",((java.sql.Timestamp)tx.get("expires_at")).toInstant().toString(),"client_id",client(id),"response_type","vp_token","response_mode","direct_post","response_uri",base+"/vp/response/"+id,"nonce",tx.get("nonce"),"state",id,"dcql_query",Map.of("credentials",List.of(Map.of("id",type,"format","dc+sd-jwt","meta",Map.of("vct_values",List.of(vct(type))),"claims",claims)))));
        if(cutoff!=null) body.put("passport_check_after",cutoff.toString());
        return JSON.writeValueAsString(body);
    }
    String client(String id) { return "redirect_uri:"+base+"/vp/response/"+id; }
    String vct(String type) { return (type.equals("staff")?base:passportIssuer)+"/vct/"+(type.equals("staff")?"BankStaffCredential":"PassportCredential"); }
    Map<String,Object> transaction(String id) { var rows=db.queryForList("select * from bank_presentation where id=? and expires_at>now()",id); require(rows.size()==1,"Presentation expired"); return rows.getFirst(); }
    @PostMapping(value="/vp/response/{id}",produces="application/json") @ResponseBody @Transactional String response(@PathVariable String id,@RequestParam String state,@RequestParam("vp_token") String vp) throws Exception {
        require(id.equals(state),"Wrong state");
        var tx=db.queryForMap("select * from bank_presentation where id=? and expires_at>now() for update",id); require(!Boolean.TRUE.equals(tx.get("complete")),"Presentation already used");
        String type=tx.get("hire_id")==null?"staff":"passport";
        var entry=JSON.readTree(vp).path(type); require(entry.isArray() && entry.size()==1 && entry.get(0).isTextual(),"Expected one credential");
        var query=CredentialQuery.builder(type,CredentialFormat.DC_SD_JWT).meta(new SdJwtVcMeta(List.of(vct(type)))).build();
        IssuerKeyResolver resolver=(issuer,kid,chain)-> {
            if(!issuer.equals(type.equals("staff")?base:passportIssuer)) return Optional.empty();
            return Optional.of(JSON.valueToTree((type.equals("staff")?bankKey:passportKey).toJSONObject()));
        };
        var verified=new SdJwtVerifier().verify(new PresentationEntry.StringPresentation(entry.get(0).asText()),new PresentationVerificationParams(query,(String)tx.get("nonce"),client(id),client(id),base+"/vp/response/"+id,Optional.empty(),resolver,Clock.systemUTC()));
        var c=verified.verifiedClaims(); require(vct(type).equals(c.path("vct").asText()),"Wrong credential type"); require(c.has("exp") && c.path("exp").asLong()>Instant.now().getEpochSecond(),"Expired credential");
        UUID staff=null;
        if(type.equals("passport")) {
            UUID hire=(UUID)tx.get("hire_id"); require(freshPassport(c,passportCheckAfter(hire)),"A fresh Passport check is required. Complete Identity Proofing again."); require(PassportEvidencePolicy.accepts(c),"Passport credential lacks acceptable proofing evidence or is expired"); require(!c.path("family_name").asText().isBlank() && !c.path("assurance_level").asText().isBlank(),"Missing identity or assurance");
            LocalDate birth=LocalDate.parse(c.path("birth_date").asText());
            require(db.update("update bank_hire set verified_given=?,verified_family=?,verified_birth=?,holder_jwk=?,status='REVIEW' where id=? and status='INVITED'",c.path("given_name").asText(),c.path("family_name").asText(),birth,verified.holderKeyConfirmed().orElseThrow().toString(),hire)==1,"Hire is not awaiting identity"); audit(hire,"IDENTITY_PRESENTED","applicant");
        } else {
            require(base.equals(c.path("bank_id").asText()),"Wrong bank"); staff=UUID.fromString(c.path("staff_id").asText()); active(staff);
            var current=db.queryForMap("select issued_credential from bank_hire where id=?",staff);
            require(current.get("issued_credential") instanceof String stored && stored.split("~",2)[0].equals(entry.get(0).asText().split("~",2)[0]),"Staff credential has been superseded");
        }
        db.update("update bank_presentation set complete=true,staff_id=? where id=?",staff,id);
        return "{}";
    }
    @GetMapping(value="/vp/status/{id}",produces="application/json") @ResponseBody
    String presentationStatus(@PathVariable String id, HttpSession session) {
        Object secret=session.getAttribute("vp:"+id);
        if(secret==null) throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Open the request in its original browser");
        var rows=db.queryForList("select complete,expires_at,browser_secret_hash from bank_presentation where id=?",id);
        if(rows.size()!=1 || !hash(secret.toString()).equals(rows.getFirst().get("browser_secret_hash")))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Open the request in its original browser");
        var tx=rows.getFirst();
        String status=!((java.sql.Timestamp)tx.get("expires_at")).toInstant().isAfter(Instant.now()) ? "expired" : Boolean.TRUE.equals(tx.get("complete")) ? "complete" : "pending";
        return "{\"status\":\""+status+"\"}";
    }
    @GetMapping("/vp/result/{id}") String result(@PathVariable String id,HttpSession session,jakarta.servlet.http.HttpServletRequest servletRequest) {
        var tx=transaction(id); Object secret=session.getAttribute("vp:"+id);
        require(secret!=null && hash(secret.toString()).equals(tx.get("browser_secret_hash")) && Boolean.TRUE.equals(tx.get("complete")),"Presentation has not completed in this browser");
        session.removeAttribute("vp:"+id);
        if(tx.get("staff_id")!=null) { servletRequest.changeSessionId(); session.setAttribute("staff",tx.get("staff_id").toString()); return "redirect:/staff"; }
        return "redirect:/onboarding";
    }
    @PostMapping("/onboarding/offer") String offer(HttpSession session,Model model) throws Exception {
        var h=db.queryForMap("select * from bank_hire where id=?",applicant(session)); require(Set.of("APPROVED","ACTIVE").contains(h.get("status")),"HR approval required");
        String offer=staffOffer(h); model.addAttribute("offer",offer); model.addAttribute("walletUrl",offerUri(offer)); model.addAttribute("qrImage",WalletQr.image((String)model.getAttribute("walletUrl"))); return "offer";
    }
    /** A one-time (10 minute) pre-authorized offer of the staff credential, bound to the holder key the applicant's Passport presentation proved. */
    String staffOffer(Map<String,Object> h) throws Exception {
        String code=token(); codes.save(code,new PreAuthorizedCodeSession(List.of("BankStaffCredential"),Optional.empty(),Map.of("staff_id",h.get("id").toString(),"bank_id",base,"given_name",(String)h.get("verified_given"),"family_name",(String)h.get("verified_family"),"department",(String)h.get("department")),Instant.now().plusSeconds(600)));
        return JSON.writeValueAsString(Map.of("credential_issuer",base,"credential_configuration_ids",List.of("BankStaffCredential"),"grants",Map.of("urn:ietf:params:oauth:grant-type:pre-authorized_code",Map.of("pre-authorized_code",code)),"bank_holder_jwk",JSON.readTree((String)h.get("holder_jwk"))));
    }
    static String offerUri(String offer) { return "openid-credential-offer://?credential_offer="+java.net.URLEncoder.encode(offer,java.nio.charset.StandardCharsets.UTF_8); }
    @ExceptionHandler(com.darkedges.oid4vp.core.response.PresentationVerificationException.class)
    org.springframework.http.ResponseEntity<String> presentationRejected(Exception error) {
        return org.springframework.http.ResponseEntity.badRequest().contentType(org.springframework.http.MediaType.APPLICATION_JSON).body("{\"error\":\"invalid_presentation\"}");
    }
    void active(UUID id) { require(db.queryForObject("select count(*) from bank_hire h where h.id=? and h.status='ACTIVE' and not exists (select 1 from bank_hire newer where newer.previous_hire_id=h.id)",Integer.class,id)==1,"Staff access is inactive"); }
    @GetMapping({"/staff", "/staff/"}) String staff(HttpSession session,Model m) { require(session.getAttribute("staff")!=null,"Sign in with your staff credential"); UUID id=UUID.fromString(session.getAttribute("staff").toString()); active(id); m.addAttribute("hire",db.queryForMap("select * from bank_hire where id=?",id)); return "staff"; }
    void audit(UUID id,String action,String actor) { db.update("insert into bank_audit(hire_id,action,actor) values (?,?,?)",id,action,actor); }
    void audit(UUID id,String action,String actor,String channel) { db.update("insert into bank_audit(hire_id,action,actor,channel) values (?,?,?,?)",id,action,actor,channel); }
}
