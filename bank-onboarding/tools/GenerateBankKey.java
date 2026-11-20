import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.Base64;

// Run with: java tools/GenerateBankKey.java /absolute/path/bank-private.jwk
class GenerateBankKey {
 static String b(BigInteger n) {
  byte[] source=n.toByteArray(), fixed=new byte[32];
  int length=Math.min(source.length,32);
  System.arraycopy(source,source.length-length,fixed,32-length,length);
  return Base64.getUrlEncoder().withoutPadding().encodeToString(fixed);
 }
 public static void main(String[] args) throws Exception {
  if(args.length!=1) throw new IllegalArgumentException("Provide an output path outside source control");
  var gen=KeyPairGenerator.getInstance("EC"); gen.initialize(new ECGenParameterSpec("secp256r1")); var pair=gen.generateKeyPair();
  var pub=(ECPublicKey)pair.getPublic(); var priv=(ECPrivateKey)pair.getPrivate();
  String publicKey="{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"bank-staff-1\",\"x\":\""+b(pub.getW().getAffineX())+"\",\"y\":\""+b(pub.getW().getAffineY())+"\"";
  Files.writeString(Path.of(args[0]),publicKey+",\"d\":\""+b(priv.getS())+"\"}", StandardOpenOption.CREATE_NEW);
  Files.writeString(Path.of(args[0]+".public"),publicKey+"}", StandardOpenOption.CREATE_NEW);
 }
}
