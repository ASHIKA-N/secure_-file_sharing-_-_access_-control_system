package com.securefiles;

import com.securefiles.config.OracleSetup;
import java.nio.file.*;
import org.apache.catalina.loader.WebappLoader;
import org.apache.catalina.startup.Tomcat;

/** Local launcher. Tomcat stays a development dependency outside the deployable WAR. */
public final class LocalServer {
  public static void main(String[] args) throws Exception {
    OracleSetup.main(new String[0]);
    Path base = Path.of(".tools/tomcat").toAbsolutePath();
    Files.createDirectories(base);
    Path stopFile = base.resolve("stop.request");
    Files.deleteIfExists(stopFile);
    Tomcat server = new Tomcat();
    server.setBaseDir(base.toString());
    server.setPort(parsePort(System.getenv().getOrDefault("SF_PORT", "8080")));
    server.getConnector().setProperty("address", "127.0.0.1");
    server.enableNaming();
    var context =
        server.addWebapp("/securefiles", Path.of("target/securefiles").toAbsolutePath().toString());
    context.setParentClassLoader(LocalServer.class.getClassLoader());
    WebappLoader loader = new WebappLoader();
    loader.setDelegate(true);
    context.setLoader(loader);
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  try {
                    server.stop();
                    server.destroy();
                  } catch (Exception ignored) {
                  }
                }));
    try {
      int boundPort = startConnector(server);
      if (!context.getState().isAvailable())
        throw new IllegalStateException(
            "Application startup failed. Check Oracle credentials and startup messages.");
      System.out.println(
          "Open http://localhost:"
              + boundPort
              + "/securefiles/login (run scripts/stop.ps1 in another terminal to stop cleanly)");
      while (!Files.exists(stopFile)) Thread.sleep(500);
    } finally {
      server.stop();
      server.destroy();
      Files.deleteIfExists(stopFile);
    }
  }

  static int parsePort(String value) {
    try {
      int port = Integer.parseInt(value);
      if (port >= 1 && port <= 65535) return port;
    } catch (NumberFormatException ignored) {
    }
    throw new IllegalArgumentException("SF_PORT must be a port number from 1 to 65535.");
  }

  static int startConnector(Tomcat server) throws Exception {
    server.start();
    int port = server.getConnector().getLocalPort();
    if (!server.getConnector().getState().isAvailable() || port < 1)
      throw new IllegalStateException(
          "Could not listen on port "
              + server.getConnector().getPort()
              + ". Another application instance may already be running. Stop it with"
              + " scripts/stop.ps1 or choose another -Port. No login URL is available until the"
              + " connector starts.");
    return port;
  }
}
