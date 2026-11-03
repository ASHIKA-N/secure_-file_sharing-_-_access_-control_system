package com.securefiles.config;

import java.nio.file.*;
import java.util.*;

public record AdvancedConfig(
    byte[] otpSecret,
    byte[] checkpointSecret,
    Path checkpoints,
    Path mailbox,
    String mailMode,
    int deniedThreshold,
    int reshareThreshold,
    int downloadThreshold,
    int distinctThreshold,
    int alertCooldownSeconds) {
  public static AdvancedConfig environment(Path storage) {
    String mode = System.getenv().getOrDefault("SF_MAIL_MODE", "SMTP");
    if (!Set.of("LOCAL", "SMTP").contains(mode))
      throw new IllegalStateException("SF_MAIL_MODE must be LOCAL or SMTP.");
    return new AdvancedConfig(
        secret("SF_OTP_SECRET"),
        secret("SF_AUDIT_SECRET"),
        privatePath(Path.of(Settings.required("SF_CHECKPOINT_DIR"))),
        privatePath(
            Path.of(
                System.getenv()
                    .getOrDefault(
                        "SF_LOCAL_MAILBOX_DIR",
                        storage.resolveSibling("local-mailbox").toString()))),
        mode,
        positive("SF_ALERT_DENIED", 10),
        positive("SF_ALERT_RESHARE", 5),
        positive("SF_ALERT_DOWNLOADS", 20),
        positive("SF_ALERT_DISTINCT", 10),
        positive("SF_ALERT_COOLDOWN_SECONDS", 900));
  }

  private static Path privatePath(Path path) {
    String base = System.getProperty("catalina.base");
    if (!path.isAbsolute()
        || base != null && path.normalize().startsWith(Path.of(base).toAbsolutePath().normalize()))
      throw new IllegalStateException(
          "Checkpoint and mailbox directories must be absolute and outside Tomcat.");
    return path.toAbsolutePath().normalize();
  }

  private static byte[] secret(String name) {
    try {
      byte[] key = Base64.getDecoder().decode(Settings.required(name));
      if (key.length < 32) throw new IllegalArgumentException();
      return key;
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(
          name + " must be Base64 encoding of at least 32 random bytes.");
    }
  }

  private static int positive(String name, int fallback) {
    int n = Integer.parseInt(System.getenv().getOrDefault(name, "" + fallback));
    if (n < 1) throw new IllegalStateException(name + " must be positive.");
    return n;
  }

  public static AdvancedConfig testing(Path root) {
    byte[] a = new byte[32], b = new byte[32];
    Arrays.fill(a, (byte) 21);
    Arrays.fill(b, (byte) 47);
    return new AdvancedConfig(
        a,
        b,
        root.resolve("test-checkpoints"),
        root.resolve("test-mailbox"),
        "LOCAL",
        10,
        5,
        20,
        10,
        900);
  }
}
