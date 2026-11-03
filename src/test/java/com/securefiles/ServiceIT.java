package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import com.securefiles.entity.*;
import com.securefiles.exception.AppException;
import com.securefiles.repository.Database;
import com.securefiles.security.Crypto;
import com.securefiles.service.*;
import java.io.IOException;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ServiceIT {
  @TempDir Path root;
  Database db;
  AppService service;
  MutableClock clock;
  long anu, bala, chitra, admin;
  String file;

  static class MutableClock extends Clock {
    Instant now = Instant.parse("2026-11-02T12:00:00Z");

    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    public Clock withZone(ZoneId zone) {
      return this;
    }

    public Instant instant() {
      return now;
    }
  }

  @BeforeEach
  void setup() throws Exception {
    db =
        new Database(
            "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=Oracle;DB_CLOSE_DELAY=-1", "sa", "", true);
    clock = new MutableClock();
    service =
        new AppService(db, new FileStorage(root), new Crypto(CryptoTest.key(1)), clock, 104857600);
    anu =
        service.register(
            "Anu", "Anu@example.test", "a useful long passphrase", "a useful long passphrase");
    bala =
        service.register(
            "Bala", "bala@example.test", "a useful long passphrase", "a useful long passphrase");
    chitra =
        service.register(
            "Chitra",
            "chitra@example.test",
            "a useful long passphrase",
            "a useful long passphrase");
    admin = service.bootstrapAdmin("Admin", "admin@example.test", "a useful long passphrase");
    file = service.upload(anu, "report.txt", "private report".getBytes(), "College project");
  }

  @AfterEach
  void close() {
    db.close();
  }

  @Test
  void registrationLoginDuplicateAndDisabledAccounts() {
    assertEquals(anu, service.login(" ANU@example.test ", "a useful long passphrase", "local"));
    assertThrows(AppException.class, () -> service.login("anu@example.test", "invalid", "local"));
    assertThrows(
        AppException.class,
        () ->
            service.register(
                "Other",
                "anu@example.test",
                "a useful long passphrase",
                "a useful long passphrase"));
    service.setActive(admin, anu, false);
    assertThrows(
        AppException.class,
        () -> service.login("anu@example.test", "a useful long passphrase", "local"));
    assertThrows(AppException.class, () -> service.account(anu));
  }

  @Test
  void loginThrottleIsBoundedAndExpires() {
    for (int i = 0; i < 5; i++)
      assertEquals(
          401,
          assertThrows(AppException.class, () -> service.login("anu@example.test", "wrong", "host"))
              .status);
    assertEquals(
        429,
        assertThrows(
                AppException.class,
                () -> service.login("anu@example.test", "a useful long passphrase", "host"))
            .status);
    clock.now = clock.now.plusSeconds(300);
    assertEquals(anu, service.login("anu@example.test", "a useful long passphrase", "host"));
  }

  @Test
  void ownerRecipientUnrelatedAndAdminRules() {
    assertArrayEquals("private report".getBytes(), service.download(anu, file).bytes());
    service.share(anu, file, "bala@example.test", null);
    assertArrayEquals("private report".getBytes(), service.download(bala, file).bytes());
    assertEquals(
        404, assertThrows(AppException.class, () -> service.download(chitra, file)).status);
    assertEquals(404, assertThrows(AppException.class, () -> service.download(admin, file)).status);
    assertFalse(service.users(admin, "", 0).isEmpty());
    assertThrows(AppException.class, () -> service.users(bala, "", 0));
    assertEquals(
        404,
        assertThrows(
                AppException.class, () -> service.download(chitra, UUID.randomUUID().toString()))
            .status);
  }

  @Test
  void exactExpiryRevocationAndDisabledOwner() {
    service.share(anu, file, "bala@example.test", clock.now.plusSeconds(60));
    clock.now = clock.now.plusSeconds(59);
    service.checkDownload(bala, file);
    clock.now = clock.now.plusSeconds(1);
    assertThrows(AppException.class, () -> service.checkDownload(bala, file));
    service.share(anu, file, "bala@example.test", null);
    long grant =
        db.tx(s -> s.createQuery("from FilePermission", FilePermission.class).getSingleResult().id);
    service.revoke(anu, file, grant);
    assertThrows(AppException.class, () -> service.download(bala, file));
    service.share(anu, file, "bala@example.test", null);
    service.setActive(admin, anu, false);
    assertThrows(AppException.class, () -> service.download(bala, file));
    assertTrue(service.files(bala, "", 0, true).isEmpty());
  }

  @Test
  void recipientsCannotManageOrReshare() {
    service.share(anu, file, "bala@example.test", null);
    long grant =
        db.tx(s -> s.createQuery("from FilePermission", FilePermission.class).getSingleResult().id);
    assertThrows(AppException.class, () -> service.share(bala, file, "chitra@example.test", null));
    assertThrows(AppException.class, () -> service.revoke(bala, file, grant));
    assertThrows(AppException.class, () -> service.delete(bala, file));
    assertThrows(AppException.class, () -> service.describe(bala, file, "changed"));
    assertThrows(AppException.class, () -> service.share(anu, file, "anu@example.test", null));
    service.share(anu, file, "bala@example.test", null);
    long count =
        db.tx(
            s ->
                s.createQuery("select count(p) from FilePermission p", Long.class)
                    .getSingleResult());
    assertEquals(1L, count);
  }

  @Test
  void deletionBlocksAccessRetainsAuditAndRetriesPhysicalCleanup() throws Exception {
    FileStorage failing =
        new FileStorage(root) {
          @Override
          public void delete(String key) throws IOException {
            throw new IOException("simulated disk failure");
          }
        };
    AppService delayed =
        new AppService(db, failing, new Crypto(CryptoTest.key(1)), clock, 104857600);
    service.share(anu, file, "bala@example.test", null);
    String key = db.tx(s -> s.find(StoredFile.class, file).storageKey);
    delayed.delete(anu, file);
    assertTrue(Files.exists(root.resolve(key + ".bin")));
    assertThrows(AppException.class, () -> service.download(bala, file));
    service.cleanup();
    assertFalse(Files.exists(root.resolve(key + ".bin")));
    assertFalse(service.activity(admin, true, null, "DELETE", null, null, null, 0).isEmpty());
  }

  @Test
  void corruptedCiphertextExposesNoPlaintext() throws Exception {
    String key = db.tx(s -> s.find(StoredFile.class, file).storageKey);
    Path path = root.resolve(key + ".bin");
    byte[] encrypted = Files.readAllBytes(path);
    encrypted[encrypted.length - 1] ^= 1;
    Files.write(path, encrypted);
    assertEquals(404, assertThrows(AppException.class, () -> service.download(anu, file)).status);
  }

  @Test
  void failedWriteRollsBackAndCleansTemporaryFile() throws Exception {
    FileStorage failing =
        new FileStorage(root) {
          @Override
          public void write(String key, byte[] bytes) throws IOException {
            super.write(key, bytes);
            throw new IOException("simulated failure");
          }
        };
    AppService broken =
        new AppService(db, failing, new Crypto(CryptoTest.key(1)), clock, 104857600);
    assertThrows(
        IllegalStateException.class,
        () -> broken.upload(anu, "second.txt", "another document".getBytes(), ""));
    try (var files = Files.list(root)) {
      assertEquals(1, files.filter(p -> p.getFileName().toString().endsWith(".bin")).count());
    }
    assertEquals(1L, service.dashboard(anu).get("owned"));
  }

  @Test
  void simultaneousUploadsCannotBypassQuota() throws Exception {
    service.delete(anu, file);
    AppService limited =
        new AppService(db, new FileStorage(root), new Crypto(CryptoTest.key(1)), clock, 20);
    ExecutorService executor = Executors.newFixedThreadPool(2);
    CountDownLatch start = new CountDownLatch(1);
    Callable<Boolean> upload =
        () -> {
          start.await();
          try {
            limited.upload(anu, "small.txt", "fifteen letters".getBytes(), "");
            return true;
          } catch (AppException e) {
            return false;
          }
        };
    try {
      Future<Boolean> first = executor.submit(upload), second = executor.submit(upload);
      start.countDown();
      assertNotEquals(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
      assertTrue((Long) limited.dashboard(anu).get("used") <= 20);
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void schemaConstraintsAndDtoBoundaries() {
    assertFalse(service.details(anu, file).containsKey("wrappedKey"));
    assertFalse(service.account(anu).containsKey("passwordHash"));
    assertThrows(
        RuntimeException.class,
        () ->
            db.tx(
                s -> {
                  User u = new User();
                  u.name = "Duplicate";
                  u.email = "anu@example.test";
                  u.passwordHash = "not used";
                  u.createdAt = clock.instant();
                  s.persist(u);
                  return null;
                }));
    assertEquals(1, service.files(anu, "report", 0, false).size());
    assertTrue(service.files(anu, "missing", 0, false).isEmpty());
  }
}
