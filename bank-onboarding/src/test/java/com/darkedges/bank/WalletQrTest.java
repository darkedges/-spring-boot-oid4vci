package com.darkedges.bank;

import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import org.junit.jupiter.api.Test;
import javax.imageio.ImageIO;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import static org.assertj.core.api.Assertions.assertThat;

class WalletQrTest {
    @Test void roundTripsPresentationAndCredentialOfferLinks() throws Exception {
        for (String url : new String[]{
                "openid4vp://?request_uri=https%3A%2F%2Fhr.bank.darkedges.com%2Fvp%2Frequest%2Fexample",
                "openid-credential-offer://?credential_offer=" + java.net.URLEncoder.encode(
                        "{\"credential_issuer\":\"https://hr.bank.darkedges.com\",\"credential_configuration_ids\":[\"BankStaffCredential\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"" + "a".repeat(43) + "\"}},\"bank_holder_jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + "b".repeat(43) + "\",\"y\":\"" + "c".repeat(43) + "\"}}", java.nio.charset.StandardCharsets.UTF_8)}) {
            String data = WalletQr.image(url);
            assertThat(data).startsWith("data:image/png;base64,");
            var image = ImageIO.read(new ByteArrayInputStream(Base64.getDecoder().decode(data.substring(data.indexOf(',')+1))));
            var source = new RGBLuminanceSource(image.getWidth(),image.getHeight(),image.getRGB(0,0,image.getWidth(),image.getHeight(),null,0,image.getWidth()));
            assertThat(new MultiFormatReader().decode(new BinaryBitmap(new HybridBinarizer(source))).getText()).isEqualTo(url);
        }
    }
}
