package com.securefiles.service;

import com.securefiles.config.AdvancedConfig;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class OtpDelivery {
  private final AdvancedConfig config;

  public OtpDelivery(AdvancedConfig config) {
    this.config = config;
  }

  public void send(long user, String email, String challenge, String code) throws Exception {
    String text =
        "Your Secure File Sharing verification code is "
            + code
            + ". It expires in five minutes. Challenge: "
            + challenge;
    if (config.mailMode().equals("LOCAL")) {
      Files.createDirectories(config.mailbox());
      FileStorage.restrict(config.mailbox());
      Path path = config.mailbox().resolve(user + "-" + challenge + ".txt");
      Files.createFile(path);
      FileStorage.restrict(path);
      Files.writeString(
          path,
          "DEVELOPMENT LOCAL MAILBOX — no email was sent.\nTo: " + email + "\n" + text,
          StandardCharsets.UTF_8);
      return;
    }
    String host = required("SF_SMTP_HOST"),
        username = System.getenv("SF_SMTP_USER"),
        password = System.getenv("SF_SMTP_PASSWORD");
    Properties p = new Properties();
    p.setProperty("mail.smtp.host", host);
    p.setProperty("mail.smtp.port", System.getenv().getOrDefault("SF_SMTP_PORT", "587"));
    p.setProperty("mail.smtp.starttls.enable", "true");
    p.setProperty("mail.smtp.starttls.required", "true");
    p.setProperty("mail.smtp.ssl.checkserveridentity", "true");
    p.setProperty("mail.smtp.connectiontimeout", "5000");
    p.setProperty("mail.smtp.timeout", "5000");
    p.setProperty("mail.smtp.writetimeout", "5000");
    p.setProperty("mail.smtp.auth", String.valueOf(username != null));
    Session session =
        Session.getInstance(
            p,
            username == null
                ? null
                : new Authenticator() {
                  protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                  }
                });
    MimeMessage message = new MimeMessage(session);
    message.setFrom(new InternetAddress(required("SF_SMTP_FROM")));
    message.setRecipient(Message.RecipientType.TO, new InternetAddress(email, true));
    message.setSubject("Secure File Sharing verification", "UTF-8");
    message.setText(text, "UTF-8");
    Transport.send(message);
  }

  private String required(String name) {
    String s = System.getenv(name);
    if (s == null || s.isBlank())
      throw new IllegalStateException("SMTP configuration missing: " + name);
    return s;
  }

  public List<String> localMessages(long user) {
    if (!config.mailMode().equals("LOCAL")) return List.of();
    try {
      if (!Files.isDirectory(config.mailbox())) return List.of();
      try (var paths = Files.list(config.mailbox())) {
        return paths
            .filter(p -> p.getFileName().toString().startsWith(user + "-"))
            .sorted(Comparator.comparing(Path::toString).reversed())
            .limit(20)
            .map(
                p -> {
                  try {
                    return Files.readString(p);
                  } catch (Exception e) {
                    return "Local message unavailable.";
                  }
                })
            .toList();
      }
    } catch (Exception e) {
      throw new IllegalStateException("Cannot read the local mailbox", e);
    }
  }

  public void cleanup(java.time.Instant before) {
    try {
      if (Files.isDirectory(config.mailbox()))
        try (var paths = Files.list(config.mailbox())) {
          for (Path p : paths.toList())
            if (Files.isRegularFile(p) && Files.getLastModifiedTime(p).toInstant().isBefore(before))
              Files.deleteIfExists(p);
        }
    } catch (Exception e) {
      System.err.println("Local mailbox cleanup deferred.");
    }
  }
}
