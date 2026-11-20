package com.darkedges.bank;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.qrcode.QRCodeWriter;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;
import javax.imageio.ImageIO;

/** Local QR generation keeps personal request and offer links inside the bank. */
final class WalletQr {
    static String image(String walletUrl) {
        try {
            var matrix = new QRCodeWriter().encode(walletUrl, BarcodeFormat.QR_CODE, 640, 640,
                    Map.of(EncodeHintType.CHARACTER_SET, "UTF-8", EncodeHintType.MARGIN, 4));
            var image = new BufferedImage(matrix.getWidth(), matrix.getHeight(), BufferedImage.TYPE_INT_RGB);
            for (int y = 0; y < matrix.getHeight(); y++)
                for (int x = 0; x < matrix.getWidth(); x++) image.setRGB(x, y, matrix.get(x, y) ? 0 : 0xffffff);
            var bytes = new ByteArrayOutputStream(); ImageIO.write(image, "png", bytes);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(bytes.toByteArray());
        } catch (Exception failed) { throw new IllegalStateException("Could not generate wallet QR code", failed); }
    }
}
