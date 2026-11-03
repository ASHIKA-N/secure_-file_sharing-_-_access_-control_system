package com.securefiles.config;

import java.nio.file.Path;

public record Settings(
    String url,
    String user,
    String password,
    Path storage,
    String master,
    long quota,
    boolean secure) {
  public static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank())
      throw new IllegalStateException(
          "Set environment variable " + name + " before starting Tomcat.");
    return value;
  }

  public static Settings environment() {
    String path = required("SF_STORAGE_DIR");
    if (!Path.of(path).isAbsolute())
      throw new IllegalStateException(
          "SF_STORAGE_DIR must be an absolute directory outside Tomcat.");
    long quota = Long.parseLong(System.getenv().getOrDefault("SF_QUOTA_BYTES", "104857600"));
    if (quota < 1) throw new IllegalStateException("SF_QUOTA_BYTES must be positive.");
    return new Settings(
        required("SF_DB_URL"),
        required("SF_DB_USER"),
        required("SF_DB_PASSWORD"),
        Path.of(path),
        required("SF_MASTER_KEY"),
        quota,
        Boolean.parseBoolean(System.getenv().getOrDefault("SF_COOKIE_SECURE", "false")));
  }
}
