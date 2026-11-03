package com.securefiles.config;

import com.securefiles.repository.Database;
import com.securefiles.security.Crypto;
import com.securefiles.service.*;
import jakarta.servlet.*;
import java.nio.file.Path;
import java.time.Clock;
import java.util.concurrent.*;

public class AppContext implements ServletContextListener {
  public static final String SERVICE = AppService.class.getName();
  private Database db;
  private ScheduledExecutorService cleaner;

  @Override
  public void contextInitialized(ServletContextEvent event) {
    ServletContext context = event.getServletContext();
    context.getSessionCookieConfig().setHttpOnly(true);
    context.getSessionCookieConfig().setAttribute("SameSite", "Lax");
    // Integration tests supply an isolated service; production never reads a test profile from
    // HTTP.
    if (context.getAttribute(SERVICE) != null) return;
    try {
      Settings settings = Settings.environment();
      Crypto crypto = new Crypto(settings.master());
      String deployed = context.getRealPath("/");
      String base = System.getProperty("catalina.base");
      if (deployed != null
              && settings.storage().normalize().startsWith(Path.of(deployed).normalize())
          || base != null && settings.storage().normalize().startsWith(Path.of(base).normalize()))
        throw new IllegalStateException(
            "SF_STORAGE_DIR must be outside the Tomcat directory and deployed WAR.");
      FileStorage storage = new FileStorage(settings.storage());
      db = new Database(settings.url(), settings.user(), settings.password(), false);
      AppService service = new AppService(db, storage, crypto, Clock.systemUTC(), settings.quota());
      context.setAttribute(SERVICE, service);
      context.getSessionCookieConfig().setSecure(settings.secure());
      cleaner =
          Executors.newSingleThreadScheduledExecutor(
              r -> {
                Thread t = new Thread(r, "securefiles-cleanup");
                t.setDaemon(true);
                return t;
              });
      cleaner.scheduleWithFixedDelay(
          () -> {
            try {
              service.cleanup();
              service.advanced().maintenance();
            } catch (RuntimeException e) {
              context.log("Storage cleanup deferred", e);
            }
          },
          60,
          60,
          TimeUnit.SECONDS);
    } catch (Exception e) {
      if (db != null) db.close();
      throw new IllegalStateException("Secure Files startup failed: " + e.getMessage(), e);
    }
  }

  @Override
  public void contextDestroyed(ServletContextEvent event) {
    if (cleaner != null) {
      cleaner.shutdownNow();
      try {
        cleaner.awaitTermination(10, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    if (db != null) db.close();
  }

  public static AppService service(ServletContext context) {
    return (AppService) context.getAttribute(SERVICE);
  }
}
