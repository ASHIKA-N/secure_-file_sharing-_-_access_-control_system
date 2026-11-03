package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import com.securefiles.exception.AppException;
import com.securefiles.security.*;
import java.security.GeneralSecurityException;
import java.util.*;
import org.junit.jupiter.api.Test;

class CryptoTest {
  static String key(int value) {
    byte[] b = new byte[32];
    Arrays.fill(b, (byte) value);
    return Base64.getEncoder().encodeToString(b);
  }

  @Test
  void roundTripFreshKeysAndIvs() throws Exception {
    Crypto crypto = new Crypto(key(1));
    byte[] plain = "private contents".getBytes();
    var a = crypto.encrypt("one", plain);
    var b = crypto.encrypt("one", plain);
    assertArrayEquals(plain, crypto.decrypt("one", a));
    assertFalse(Arrays.equals(a.bytes(), b.bytes()));
    assertFalse(Arrays.equals(a.fileIv(), b.fileIv()));
    assertFalse(Arrays.equals(a.wrappingIv(), b.wrappingIv()));
  }

  @Test
  void wrongKeyChangedCiphertextAndMetadataFailBeforeReturn() throws Exception {
    Crypto crypto = new Crypto(key(1));
    var encrypted = crypto.encrypt("one", "private".getBytes());
    assertThrows(
        GeneralSecurityException.class, () -> new Crypto(key(2)).decrypt("one", encrypted));
    assertThrows(GeneralSecurityException.class, () -> crypto.decrypt("different-id", encrypted));
    encrypted.bytes()[0] ^= 1;
    assertThrows(GeneralSecurityException.class, () -> crypto.decrypt("one", encrypted));
  }

  @Test
  void invalidMasterKeyFailsEarly() {
    assertThrows(IllegalStateException.class, () -> new Crypto(null));
    assertThrows(IllegalStateException.class, () -> new Crypto("dummy"));
  }

  @Test
  void passwordHashingAndVerification() {
    String hash = Passwords.hash("a useful long passphrase");
    assertTrue(hash.startsWith("$argon2id$"));
    assertTrue(Passwords.verify(hash, "a useful long passphrase"));
    assertFalse(Passwords.verify(hash, "wrong password"));
  }

  @Test
  void filenameAndContentValidation() {
    UploadValidator validator = new UploadValidator();
    byte[] text = "a plain text document".getBytes();
    assertEquals("text/plain", validator.validate("report.txt", text));
    for (String name :
        List.of("../report.txt", "report.exe.txt", "report.txt.exe", "a\\b.txt", "bad\r\nname.txt"))
      assertThrows(AppException.class, () -> validator.validate(name, text));
    assertThrows(AppException.class, () -> validator.validate("image.png", text));
    assertThrows(AppException.class, () -> validator.validate("empty.txt", new byte[0]));
    assertThrows(
        AppException.class,
        () -> validator.validate("large.txt", new byte[UploadValidator.MAX_BYTES + 1]));
    assertThrows(
        AppException.class, () -> validator.validate("binary.txt", new byte[] {1, 2, 0, 5}));
  }

  @Test
  void allowedImageAndPdfFormats() throws Exception {
    UploadValidator validator = new UploadValidator();
    var image = new java.awt.image.BufferedImage(2, 2, java.awt.image.BufferedImage.TYPE_INT_RGB);
    for (String format : List.of("png", "jpeg")) {
      var output = new java.io.ByteArrayOutputStream();
      javax.imageio.ImageIO.write(image, format, output);
      assertEquals(
          format.equals("png") ? "image/png" : "image/jpeg",
          validator.validate("image." + format, output.toByteArray()));
    }
    byte[] pdf =
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    assertEquals("application/pdf", validator.validate("report.pdf", pdf));
    assertThrows(
        AppException.class,
        () -> validator.validate("broken.pdf", "%PDF-1.4 truncated".getBytes()));
  }
}
