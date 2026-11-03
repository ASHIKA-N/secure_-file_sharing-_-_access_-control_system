package com.securefiles.config;

import com.securefiles.repository.Database;
import com.securefiles.security.Crypto;
import com.securefiles.service.*;
import java.time.Clock;

public final class AdminBootstrap {
  public static void main(String[] args) throws Exception {
    Settings settings = Settings.environment();
    try (Database db = new Database(settings.url(), settings.user(), settings.password(), false)) {
      AppService service =
          new AppService(
              db,
              new FileStorage(settings.storage()),
              new Crypto(settings.master()),
              Clock.systemUTC(),
              settings.quota());
      service.bootstrapAdmin(
          Settings.required("SF_ADMIN_NAME"),
          Settings.required("SF_ADMIN_EMAIL"),
          Settings.required("SF_ADMIN_PASSWORD"));
      System.out.println("Administrator created. Remove SF_ADMIN_PASSWORD from this shell.");
    }
  }
}
