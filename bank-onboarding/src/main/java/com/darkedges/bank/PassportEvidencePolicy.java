package com.darkedges.bank;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.LocalDate;
import java.util.*;
final class PassportEvidencePolicy {
    static boolean accepts(JsonNode claims) {
        String assurance="showcase".equals(System.getProperty("spring.profiles.active")) && Boolean.getBoolean("showcase.simulated") ? "showcase-simulated" : "poc-demo";
        if (!assurance.equals(claims.path("assurance_level").asText()) || !claims.path("evidence").isTextual()) return false;
        Map<String,String> fields=new HashMap<>();
        for (String part:claims.path("evidence").asText().split(";",-1)) {
            int at=part.indexOf('='); if(at<1) return false;
            if(fields.putIfAbsent(part.substring(0,at).trim(),part.substring(at+1).trim())!=null) return false;
        }
        try { if(LocalDate.parse(claims.path("expiry_date").asText()).isBefore(LocalDate.now(java.time.ZoneOffset.UTC))) return false; }
        catch(Exception invalid) { return false; }
        return "passed".equals(fields.get("liveness")) && "passed".equals(fields.get("face-match"))
            && "verified".equals(fields.get("chip-signature")) && "verified".equals(fields.get("csca-chain"))
            && "verified".equals(fields.get("portrait-from-chip"));
    }
}
