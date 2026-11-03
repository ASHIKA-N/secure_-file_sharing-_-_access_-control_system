package com.securefiles.config;

import java.nio.file.*;
import java.sql.*;

/** Explicit local setup only; normal Tomcat startup still validates the schema. */
public final class OracleSetup {
  public static void main(String[] args) throws Exception {
    initialize(
        Settings.required("SF_DB_URL"),
        Settings.required("SF_DB_USER"),
        Settings.required("SF_DB_PASSWORD"));
  }

  public static void initialize(String url, String user, String password) throws Exception {
    if (!url.startsWith("jdbc:oracle:"))
      throw new IllegalArgumentException("Use an Oracle JDBC URL.");
    try (Connection connection = DriverManager.getConnection(url, user, password)) {
      connection.setAutoCommit(false);
      boolean versionExists;
      try (PreparedStatement query =
              connection.prepareStatement(
                  "select count(*) from user_tables where table_name='SCHEMA_VERSION'");
          ResultSet result = query.executeQuery()) {
        result.next();
        versionExists = result.getInt(1) == 1;
      }
      if (versionExists) {
        try (Statement query = connection.createStatement();
            ResultSet result = query.executeQuery("select max(version) from schema_version")) {
          if (!result.next()) throw new IllegalStateException("Cannot read Oracle schema version.");
          int version = result.getInt(1);
          if (version == 2) return;
          if (version == 1) {
            applyAdvanced(connection);
            return;
          }
          if (!result.wasNull())
            throw new IllegalStateException("Unsupported Oracle schema version.");
        }
      }
      try (Statement query = connection.createStatement();
          ResultSet result = query.executeQuery("select count(*) from user_tables")) {
        result.next();
        if (result.getInt(1) != (versionExists ? 1 : 0))
          throw new IllegalStateException(
              "Setup requires an empty application schema. Existing tables were preserved.");
      }
      String sql =
          Files.readString(Path.of("database/V001__initial_schema.sql"))
              .replaceAll("(?m)^--.*$", "");
      // Oracle DDL commits implicitly; failures require inspecting this dedicated schema.
      for (String statement : sql.split(";")) {
        // Resume only an empty version table left before the first application table.
        if (versionExists && statement.strip().startsWith("CREATE TABLE schema_version")) continue;
        if (!statement.isBlank())
          try (Statement query = connection.createStatement()) {
            query.execute(statement.strip());
          }
      }
      connection.commit();
      applyAdvanced(connection);
    }
  }

  private static void applyAdvanced(Connection connection) throws Exception {
    String sql =
        Files.readString(Path.of("database/V002__advanced_access.sql"))
            .replaceAll("(?m)^--.*$", "");
    for (String statement : sql.split(";"))
      if (!statement.isBlank())
        try (Statement query = connection.createStatement()) {
          query.execute(statement.strip());
        }
    connection.commit();
    System.out.println("Oracle application schema version 2 is ready.");
  }
}
