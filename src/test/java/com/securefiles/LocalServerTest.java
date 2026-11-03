package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import java.net.*;
import java.nio.file.Path;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LocalServerTest {
  @TempDir Path root;

  @Test
  void invalidPortsAreRejectedBeforeStartup() {
    for (String value : new String[] {"-1", "0", "65536", "not-a-port"})
      assertThrows(IllegalArgumentException.class, () -> LocalServer.parsePort(value));
    assertEquals(8080, LocalServer.parsePort("8080"));
  }

  @Test
  void occupiedPortDoesNotProduceNegativeLoginUrl() throws Exception {
    try (ServerSocket occupied = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
      Tomcat server = new Tomcat();
      server.setBaseDir(root.toString());
      server.setPort(occupied.getLocalPort());
      server.getConnector().setProperty("address", "127.0.0.1");
      try {
        IllegalStateException error =
            assertThrows(IllegalStateException.class, () -> LocalServer.startConnector(server));
        assertTrue(error.getMessage().contains("Could not listen on port"));
        assertTrue(error.getMessage().contains("-Port"));
      } finally {
        server.stop();
        server.destroy();
      }
    }
  }
}
