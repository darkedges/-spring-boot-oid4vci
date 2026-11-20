package com.darkedges.oid4vci.demo.issuer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import static org.assertj.core.api.Assertions.assertThat;
class ShowcaseKeyIsolationTest {
 @TempDir Path dir;
 @Test void showcaseUsesSeparateConfiguredKeyAndNormalRuntimeIgnoresIt() throws Exception {
  var key=new ECKeyGenerator(Curve.P_256).generate();var file=dir.resolve("key.jwk");Files.writeString(file,key.toJSONString());
  String profile=System.getProperty("spring.profiles.active"),path=System.getProperty("showcase.signing-key-file");
  try {
   System.clearProperty("spring.profiles.active");System.setProperty("showcase.signing-key-file",file.toString());
   assertThat(new DemoIssuerKeyConfig().issuerSigningKey().computeThumbprint()).isNotEqualTo(key.computeThumbprint());
   System.setProperty("spring.profiles.active","showcase");assertThat(new DemoIssuerKeyConfig().issuerSigningKey().computeThumbprint()).isEqualTo(key.computeThumbprint());
  } finally {if(profile==null)System.clearProperty("spring.profiles.active");else System.setProperty("spring.profiles.active",profile);if(path==null)System.clearProperty("showcase.signing-key-file");else System.setProperty("showcase.signing-key-file",path);}
 }
}
