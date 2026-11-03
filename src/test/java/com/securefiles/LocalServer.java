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
    server.setPort(Integer.parseInt(System.getenv().getOrDefault("SF_PORT", "8080")));
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
    server.start();
    if (!context.getState().isAvailable())
      throw new IllegalStateException(
          "Application startup failed. Check Oracle credentials and startup messages.");
    System.out.println(
        "Open http://localhost:"
            + server.getConnector().getLocalPort()
            + "/securefiles/login (run scripts/stop.ps1 in another terminal to stop cleanly)");
    try {
      while (!Files.exists(stopFile)) Thread.sleep(500);
    } finally {
      server.stop();
      server.destroy();
      Files.deleteIfExists(stopFile);
    }
  }
}
