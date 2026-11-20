package com.darkedges.bank;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;
class PassportEvidencePolicyTest {
 @Test void simulationAssuranceRequiresExplicitShowcaseRuntime() {
  var json=new ObjectMapper();
  var claims=json.valueToTree(Map.of("assurance_level","showcase-simulated","evidence","liveness=passed; face-match=passed; chip-signature=verified; csca-chain=verified; portrait-from-chip=verified","expiry_date","2099-12-31"));
  String profile=System.getProperty("spring.profiles.active"),flag=System.getProperty("showcase.simulated");
  try {
   System.clearProperty("spring.profiles.active");System.setProperty("showcase.simulated","true");assertThat(PassportEvidencePolicy.accepts(claims)).isFalse();
   System.setProperty("spring.profiles.active","showcase");assertThat(PassportEvidencePolicy.accepts(claims)).isTrue();
   System.clearProperty("showcase.simulated");assertThat(PassportEvidencePolicy.accepts(claims)).isFalse();
  } finally {if(profile==null)System.clearProperty("spring.profiles.active");else System.setProperty("spring.profiles.active",profile);if(flag==null)System.clearProperty("showcase.simulated");else System.setProperty("showcase.simulated",flag);}
 }

 @Test void acceptsOnlyCompleteUnambiguousProofedEvidenceAndValidPassport() {
  var json=new ObjectMapper();
  String evidence="liveness=passed; face-match=passed; chip-signature=verified; csca-chain=verified; portrait-from-chip=verified";
  assertThat(PassportEvidencePolicy.accepts(json.valueToTree(Map.of("assurance_level","poc-demo","evidence",evidence,"expiry_date","2099-01-01")))).isTrue();
  for(String bad: new String[]{"",evidence+"; liveness=passed",evidence.replace("chip-signature=verified","chip-signature=failed")})
   assertThat(PassportEvidencePolicy.accepts(json.valueToTree(Map.of("assurance_level","poc-demo","evidence",bad,"expiry_date","2099-01-01")))).isFalse();
  assertThat(PassportEvidencePolicy.accepts(json.valueToTree(Map.of("assurance_level","poc-demo","evidence",evidence,"expiry_date","2000-01-01")))).isFalse();
 }
}
