package com.securefiles.security;

import com.securefiles.exception.AppException;
import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import javax.imageio.ImageIO;
import javax.imageio.stream.ImageInputStream;
import org.apache.tika.Tika;

public final class UploadValidator {
  public static final int MAX_BYTES = 10 * 1024 * 1024;
  private static final Map<String, String> TYPES =
      Map.of(
          "pdf",
          "application/pdf",
          "txt",
          "text/plain",
          "png",
          "image/png",
          "jpg",
          "image/jpeg",
          "jpeg",
          "image/jpeg");

  public String validate(String name, byte[] bytes) {
    if (name == null
        || !name.matches("[A-Za-z0-9][A-Za-z0-9 _()-]{0,149}\\.(?i:pdf|txt|png|jpe?g)"))
      throw AppException.invalid(
          "Use a simple filename with one extension: PDF, TXT, PNG or JPEG.");
    if (bytes.length == 0 || bytes.length > MAX_BYTES)
      throw AppException.invalid("Files must contain between 1 byte and 10 MiB.");
    String ext = name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT);
    String detected = new Tika().detect(bytes);
    if (!TYPES.get(ext).equals(detected))
      throw AppException.invalid("The file contents do not match its allowed extension.");
    try {
      if (ext.equals("txt")) {
        String text =
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
        if (text.codePoints()
            .anyMatch(c -> Character.isISOControl(c) && c != 9 && c != 10 && c != 13))
          throw new IOException();
      } else if (ext.equals("pdf")) {
        String prefix = new String(bytes, 0, Math.min(bytes.length, 8), StandardCharsets.US_ASCII);
        String tail =
            new String(
                bytes,
                Math.max(0, bytes.length - 1024),
                Math.min(1024, bytes.length),
                StandardCharsets.ISO_8859_1);
        if (!prefix.startsWith("%PDF-1.") && !prefix.startsWith("%PDF-2.")) throw new IOException();
        if (!tail.stripTrailing().endsWith("%%EOF")) throw new IOException();
      } else {
        try (ImageInputStream input =
            ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
          var readers = ImageIO.getImageReaders(input);
          if (!readers.hasNext()) throw new IOException();
          var reader = readers.next();
          try {
            reader.setInput(input);
            if ((long) reader.getWidth(0) * reader.getHeight(0) > 25_000_000L)
              throw new IOException();
            if (reader.read(0) == null) throw new IOException();
          } finally {
            reader.dispose();
          }
        }
      }
    } catch (IOException | RuntimeException e) {
      throw AppException.invalid("The file format is invalid or too complex.");
    }
    return detected;
  }
}
