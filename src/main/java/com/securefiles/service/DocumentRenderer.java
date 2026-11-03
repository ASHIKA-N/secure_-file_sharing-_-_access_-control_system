package com.securefiles.service;

import com.securefiles.exception.AppException;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import javax.imageio.*;

public final class DocumentRenderer {
  public record Rendered(byte[] bytes, int pages) {}

  private static final Semaphore WORKERS = new Semaphore(2);

  public Rendered page(String mime, byte[] bytes, int page, String identity) {
    if (page < 0 || page >= 40) throw AppException.invalid("Page is outside the supported range.");
    BufferedImage image;
    int pages = 1;
    try {
      if (mime.equals("application/pdf")) {
        Rendered result = pdf("RENDER", bytes, page, "");
        image = ImageIO.read(new ByteArrayInputStream(result.bytes));
        pages = result.pages;
      } else if (mime.equals("text/plain")) {
        if (bytes.length > 250000)
          throw AppException.invalid(
              "Text exceeds the bounded viewer size. Download it if permitted.");
        String text = new String(bytes, StandardCharsets.UTF_8);
        List<String> lines = new ArrayList<>();
        for (String line : text.replace("\t", "    ").split("\\R", -1)) {
          while (line.length() > 95) {
            lines.add(line.substring(0, 95));
            line = line.substring(95);
          }
          lines.add(line);
          if (lines.size() > 40 * 65)
            throw AppException.invalid("Text exceeds the 40-page viewer limit.");
        }
        pages = Math.max(1, (lines.size() + 64) / 65);
        if (page >= pages) throw AppException.unavailable();
        image = new BufferedImage(1100, 1500, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 1100, 1500);
        g.setColor(Color.BLACK);
        g.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 17));
        int y = 45;
        for (String line : lines.subList(page * 65, Math.min(lines.size(), (page + 1) * 65))) {
          g.drawString(line, 30, y);
          y += 21;
        }
        g.dispose();
      } else if (mime.equals("image/png") || mime.equals("image/jpeg")) {
        if (page != 0) throw AppException.unavailable();
        try (var input = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
          var readers = ImageIO.getImageReaders(input);
          if (!readers.hasNext()) throw new IOException();
          var reader = readers.next();
          try {
            reader.setInput(input);
            int sample =
                Math.max(
                    1,
                    (int)
                        Math.ceil(
                            Math.max(reader.getWidth(0) / 1400.0, reader.getHeight(0) / 1800.0)));
            var params = reader.getDefaultReadParam();
            params.setSourceSubsampling(sample, sample, 0, 0);
            image = reader.read(0, params);
          } finally {
            reader.dispose();
          }
        }
      } else throw AppException.invalid("This file cannot be rendered.");
      if (image == null || (long) image.getWidth() * image.getHeight() > 3_000_000)
        throw new IOException();
      if (image.getWidth() < 600 || image.getHeight() < 300) {
        BufferedImage canvas =
            new BufferedImage(
                Math.max(600, image.getWidth()),
                Math.max(300, image.getHeight()),
                BufferedImage.TYPE_INT_RGB);
        Graphics2D background = canvas.createGraphics();
        background.setColor(Color.WHITE);
        background.fillRect(0, 0, canvas.getWidth(), canvas.getHeight());
        background.drawImage(image, (canvas.getWidth() - image.getWidth()) / 2, 0, null);
        background.dispose();
        image.flush();
        image = canvas;
      }
      Graphics2D g = image.createGraphics();
      g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, Math.max(11, image.getWidth() / 75)));
      g.setColor(new Color(255, 255, 255, 210));
      int lineHeight = Math.max(15, image.getWidth() / 60), n = 0;
      List<String> identityLines = new ArrayList<>();
      for (String original : identity.split("\n")) {
        String rest = original;
        while (rest.length() > 65) {
          identityLines.add(rest.substring(0, 65));
          rest = rest.substring(65);
        }
        identityLines.add(rest);
      }
      int top = Math.max(0, image.getHeight() - lineHeight * (identityLines.size() + 1));
      g.fillRect(0, top, image.getWidth(), image.getHeight() - top);
      g.setColor(new Color(65, 65, 65));
      for (String line : identityLines) g.drawString(line, 8, top + lineHeight * (++n));
      g.dispose();
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ImageIO.write(image, "png", out);
      image.flush();
      return new Rendered(out.toByteArray(), pages);
    } catch (IOException e) {
      throw AppException.invalid("The file could not be rendered safely.");
    }
  }

  public byte[] watermark(byte[] pdf, String identity) {
    return pdf("WATERMARK", pdf, 0, identity).bytes;
  }

  private Rendered pdf(String operation, byte[] bytes, int page, String identity) {
    if (!WORKERS.tryAcquire())
      throw new AppException(503, "The document processor is busy. Please retry.");
    Process process = null;
    ExecutorService io =
        Executors.newSingleThreadExecutor(
            r -> {
              Thread t = new Thread(r, "pdf-io");
              t.setDaemon(true);
              return t;
            });
    try {
      Set<String> paths = new LinkedHashSet<>();
      for (Class<?> type :
          new Class<?>[] {
            PdfWorker.class,
            org.apache.pdfbox.Loader.class,
            org.apache.pdfbox.io.RandomAccessReadBuffer.class,
            org.apache.fontbox.FontBoxFont.class,
            org.apache.commons.logging.LogFactory.class
          })
        paths.add(
            Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
      String java =
          Path.of(
                  System.getProperty("java.home"),
                  "bin",
                  System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java")
              .toString();
      ProcessBuilder builder =
          new ProcessBuilder(
                  java,
                  "-Xmx160m",
                  "-Djava.awt.headless=true",
                  "-cp",
                  String.join(File.pathSeparator, paths),
                  PdfWorker.class.getName())
              .redirectError(ProcessBuilder.Redirect.DISCARD);
      builder
          .environment()
          .keySet()
          .removeIf(key -> key.startsWith("SF_") && !key.equals("SF_PDF_FONT"));
      process = builder.start();
      Process child = process;
      Future<Rendered> work =
          io.submit(
              () -> {
                try (DataOutputStream in = new DataOutputStream(child.getOutputStream());
                    DataInputStream out = new DataInputStream(child.getInputStream())) {
                  in.writeUTF(operation);
                  in.writeInt(page);
                  in.writeUTF(identity);
                  in.writeInt(bytes.length);
                  in.write(bytes);
                  in.flush();
                  int pages = out.readInt(), length = out.readInt();
                  if (length < 1 || length > 24 * 1024 * 1024) throw new IOException();
                  byte[] result = out.readNBytes(length);
                  if (result.length != length) throw new IOException();
                  return new Rendered(result, pages);
                }
              });
      Rendered result = work.get(8, TimeUnit.SECONDS);
      if (!process.waitFor(1, TimeUnit.SECONDS) || process.exitValue() != 0)
        throw new IOException();
      return result;
    } catch (Exception e) {
      throw AppException.invalid(
          "PDF processing failed or exceeded its limit. Use an unsigned, unencrypted PDF of at most"
              + " 40 pages.");
    } finally {
      if (process != null) process.destroyForcibly();
      io.shutdownNow();
      WORKERS.release();
    }
  }
}
