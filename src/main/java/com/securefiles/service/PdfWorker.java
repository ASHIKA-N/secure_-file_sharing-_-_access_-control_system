package com.securefiles.service;

import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.ImageIO;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.font.*;
import org.apache.pdfbox.pdmodel.graphics.state.PDExtendedGraphicsState;
import org.apache.pdfbox.rendering.PDFRenderer;

/** Runs in a separate, memory-limited JVM; no database or encryption keys are passed. */
public final class PdfWorker {
  public static void main(String[] args) throws Exception {
    DataInputStream input = new DataInputStream(System.in);
    String action = input.readUTF();
    int page = input.readInt();
    String watermark = input.readUTF();
    int length = input.readInt();
    if (length < 1 || length > 10 * 1024 * 1024) throw new IOException("PDF size");
    byte[] bytes = input.readNBytes(length);
    if (bytes.length != length) throw new IOException("Incomplete PDF");
    try (PDDocument document = Loader.loadPDF(bytes)) {
      if (document.isEncrypted() || !document.getSignatureDictionaries().isEmpty())
        throw new IOException("Encrypted or signed PDF is unsupported");
      int pages = document.getNumberOfPages();
      if (pages < 1 || pages > 40) throw new IOException("PDF page count");
      for (PDPage p : document.getPages())
        if (p.getMediaBox().getWidth() > 10000 || p.getMediaBox().getHeight() > 10000)
          throw new IOException("PDF page dimensions");
      DataOutputStream output = new DataOutputStream(System.out);
      if (action.equals("RENDER")) {
        if (page < 0 || page >= pages) throw new IOException("Page unavailable");
        PDPage p = document.getPage(page);
        float scale =
            Math.min(
                2f,
                Math.min(1400f / p.getCropBox().getWidth(), 1800f / p.getCropBox().getHeight()));
        if (!Float.isFinite(scale) || scale <= 0) throw new IOException("Page dimensions");
        BufferedImage image = new PDFRenderer(document).renderImage(page, scale);
        ByteArrayOutputStream png = new ByteArrayOutputStream();
        ImageIO.write(image, "png", png);
        image.flush();
        output.writeInt(pages);
        output.writeInt(png.size());
        png.writeTo(output);
      } else if (action.equals("WATERMARK")) {
        Path fontPath = fontPath();
        PDType0Font font = PDType0Font.load(document, fontPath.toFile());
        StringBuilder safe = new StringBuilder();
        watermark
            .codePoints()
            .filter(c -> !Character.isISOControl(c) || c == 10)
            .forEach(
                c -> {
                  String ch = new String(Character.toChars(c));
                  try {
                    if (c != 10) font.encode(ch);
                    safe.append(ch);
                  } catch (Exception e) {
                    safe.append('?');
                  }
                });
        List<String> lines = new ArrayList<>();
        for (String original : safe.toString().split("\n")) {
          String rest = original;
          while (rest.length() > 70) {
            int split = 70;
            if (Character.isHighSurrogate(rest.charAt(split - 1))) split--;
            lines.add(rest.substring(0, split));
            rest = rest.substring(split);
          }
          lines.add(rest);
        }
        for (PDPage p : document.getPages())
          try (PDPageContentStream stream =
              new PDPageContentStream(
                  document, p, PDPageContentStream.AppendMode.APPEND, true, true)) {
            PDExtendedGraphicsState state = new PDExtendedGraphicsState();
            state.setNonStrokingAlphaConstant(.65f);
            stream.setGraphicsStateParameters(state);
            stream.setNonStrokingColor(.25f, .25f, .25f);
            float size = Math.min(9f, Math.max(2f, (p.getCropBox().getWidth() - 20) / 420f * 9f));
            stream.beginText();
            stream.setFont(font, size);
            stream.setLeading(size * 1.2f);
            stream.newLineAtOffset(
                p.getCropBox().getLowerLeftX() + 10,
                p.getCropBox().getLowerLeftY() + 10 + lines.size() * size * 1.2f);
            for (String line : lines) {
              stream.showText(line);
              stream.newLine();
            }
            stream.endText();
          }
        ByteArrayOutputStream pdf = new ByteArrayOutputStream();
        document.save(pdf);
        if (pdf.size() > 24 * 1024 * 1024) throw new IOException("Derivative too large");
        output.writeInt(pages);
        output.writeInt(pdf.size());
        pdf.writeTo(output);
      } else throw new IOException("Unsupported operation");
      output.flush();
    }
  }

  private static Path fontPath() throws IOException {
    String configured = System.getenv("SF_PDF_FONT");
    for (String path :
        List.of(
            configured == null ? "" : configured,
            System.getenv().getOrDefault("WINDIR", "C:/Windows") + "/Fonts/arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
      if (!path.isEmpty() && Files.isRegularFile(Path.of(path))) return Path.of(path);
    throw new IOException("Configure SF_PDF_FONT to a Unicode TrueType font");
  }
}
