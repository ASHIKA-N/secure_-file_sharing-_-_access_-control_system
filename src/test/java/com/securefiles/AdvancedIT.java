package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import com.securefiles.config.AdvancedConfig;
import com.securefiles.entity.*;
import com.securefiles.exception.AppException;
import com.securefiles.repository.Database;
import com.securefiles.security.*;
import com.securefiles.service.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class AdvancedIT {
  @Test
  void scheduledShareIsListedWhileContentStillRequiresHoursAndOtp() {
    advanced.share(
        anu,
        file,
        "bala@test.example",
        new AccessPolicy(true, 2, true, 2, false, null, 13 * 60, 14 * 60, "UTC", true, null),
        null);
    var rows = app.files(bala, "", 0, true);
    assertEquals(1, rows.size());
    assertEquals(false, rows.get(0).get("accessOpen"));
    assertEquals("13:00–14:00 UTC", rows.get(0).get("accessHours"));
    assertEquals(403, assertThrows(AppException.class, () -> app.download(bala, file)).status);
    assertEquals(0, downloads(bala));
    clock.now = Instant.parse("2026-11-02T13:00:00Z");
    rows = app.files(bala, "", 0, true);
    assertEquals(true, rows.get(0).get("accessOpen"));
    assertEquals(true, rows.get(0).get("otp"));
    assertEquals(428, assertThrows(AppException.class, () -> app.download(bala, file)).status);
    String challenge = advanced.startOtp(bala, file, "DOWNLOAD");
    String permit = advanced.verifyOtp(bala, challenge, code(challenge));
    assertNotNull(advanced.download(bala, file, permit, false));
    assertEquals(1, downloads(bala));
  }

  @Test
  void concurrentAuditAppendsRemainVerifiable() throws Exception {
    var workers = Executors.newFixedThreadPool(4);
    try {
      List<Callable<Boolean>> jobs = new ArrayList<>();
      for (int i = 0; i < 12; i++)
        jobs.add(
            () -> {
              advanced.denied(bala, UUID.randomUUID().toString(), "DOWNLOAD", "UNAVAILABLE");
              return true;
            });
      for (var result : workers.invokeAll(jobs)) assertTrue(result.get());
      assertEquals(true, advanced.audit().verify().get("valid"));
    } finally {
      workers.shutdownNow();
    }
  }

  @Test
  void checkpointDetectsTailTruncationEvenWithRewrittenHead() {
    Map<String, Object> point = advanced.checkpoint(admin);
    long seq = (Long) point.get("sequence");
    db.tx(
        s -> {
          String previous =
              s.createQuery("select eventHash from AuditLog where sequence=:seq", String.class)
                  .setParameter("seq", seq - 1)
                  .getSingleResult();
          s.createMutationQuery("delete from AuditLog where sequence>=:seq")
              .setParameter("seq", seq)
              .executeUpdate();
          AuditHead head = s.find(AuditHead.class, 1);
          head.sequence = seq - 1;
          head.hash = previous;
          return null;
        });
    assertEquals(false, advanced.audit().verify().get("valid"));
  }

  @Test
  void reorderingAndCheckpointAlterationAreDetected() throws Exception {
    advanced.checkpoint(admin);
    Path checkpoint;
    try (var paths = Files.list(root.resolve("test-checkpoints"))) {
      checkpoint = paths.findFirst().orElseThrow();
    }
    String original = Files.readString(checkpoint);
    Files.writeString(checkpoint, original + "tampered");
    assertEquals(false, advanced.audit().verify().get("valid"));
    Files.writeString(checkpoint, original);
    db.tx(
        s -> {
          List<AuditLog> events =
              s.createQuery("from AuditLog order by sequence", AuditLog.class)
                  .setMaxResults(2)
                  .list();
          AuditLog first = events.get(0), second = events.get(1);
          long a = first.sequence, b = second.sequence;
          first.sequence = 100000L;
          s.flush();
          second.sequence = a;
          s.flush();
          first.sequence = b;
          return null;
        });
    assertEquals(false, advanced.audit().verify().get("valid"));
  }

  @Test
  void concurrentViewInitiationsShareOneReservation() throws Exception {
    advanced.share(
        anu, file, "bala@test.example", policy(true, 1, false, null, false, false), null);
    var workers = Executors.newFixedThreadPool(2);
    try {
      var a = workers.submit(() -> advanced.openView(bala, file, "tab_a_initiation_12", null));
      var b = workers.submit(() -> advanced.openView(bala, file, "tab_b_initiation_12", null));
      assertEquals(a.get(20, TimeUnit.SECONDS).id(), b.get(20, TimeUnit.SECONDS).id());
      assertEquals(1, db.tx(s -> s.find(FilePermission.class, grant(bala)).viewsUsed).intValue());
    } finally {
      workers.shutdownNow();
    }
  }

  @Test
  void delegatedWindowsIntersectAndPinnedVersionsRemainRestricted() {
    advanced.share(
        anu,
        file,
        "bala@test.example",
        new AccessPolicy(
            true,
            null,
            true,
            null,
            true,
            clock.now.plusSeconds(7200),
            660,
            780,
            "UTC",
            false,
            file),
        null);
    advanced.share(
        bala,
        file,
        "chitra@test.example",
        new AccessPolicy(
            true,
            null,
            true,
            null,
            false,
            clock.now.plusSeconds(3600),
            720,
            840,
            "UTC",
            false,
            file),
        null);
    advanced.newVersion(anu, file, "new.txt", "another immutable version".getBytes());
    assertEquals(file, advanced.info(chitra, file).get("versionId"));
    assertThrows(
        AppException.class,
        () ->
            advanced.share(
                bala,
                file,
                "devi@test.example",
                policy(true, null, true, null, false, false),
                null));
    clock.now = Instant.parse("2026-11-02T13:00:00Z");
    assertThrows(AppException.class, () -> advanced.info(chitra, file));
  }

  @Test
  void otpPermitCannotMoveAcrossFilesAndNewConfidentialityBlocksOldViewer() {
    advanced.share(anu, file, "bala@test.example", policy(true, 3, true, null, false, true), null);
    String challenge = advanced.startOtp(bala, file, "VIEW"),
        permit = advanced.verifyOtp(bala, challenge, code(challenge));
    String other = app.upload(anu, "other.txt", "second protected file".getBytes(), "");
    advanced.share(anu, other, "bala@test.example", policy(true, 2, true, null, false, true), null);
    assertThrows(
        AppException.class, () -> advanced.openView(bala, other, "wrong_file_init_123", permit));
    var ticket = advanced.openView(bala, file, "correct_file_init12", permit);
    assertNotNull(ticket);
    advanced.share(
        anu, other, "bala@test.example", policy(true, 3, true, null, false, false), null);
    var second = advanced.openView(bala, other, "no_permit_view_123", null);
    advanced.settings(anu, other, false, "CONFIDENTIAL");
    assertEquals(
        428,
        assertThrows(
                AppException.class, () -> advanced.viewPage(bala, second.id(), second.token(), 0))
            .status);
  }

  @TempDir Path root;
  Database db;
  AppService app;
  AdvancedService advanced;
  ServiceIT.MutableClock clock;
  long anu, bala, chitra, devi, admin;
  String file;

  @BeforeEach
  void setup() throws Exception {
    db =
        new Database(
            "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=Oracle;DB_CLOSE_DELAY=-1", "sa", "", true);
    clock = new ServiceIT.MutableClock();
    app =
        new AppService(db, new FileStorage(root), new Crypto(CryptoTest.key(1)), clock, 104857600);
    advanced = app.advanced();
    String pass = "a useful long passphrase";
    anu = app.register("Anu", "anu@test.example", pass, pass);
    bala = app.register("Bala", "bala@test.example", pass, pass);
    chitra = app.register("Chitra", "chitra@test.example", pass, pass);
    devi = app.register("Devi", "devi@test.example", pass, pass);
    admin = app.bootstrapAdmin("Admin", "admin@test.example", pass);
    file = app.upload(anu, "report.txt", "Private version one".getBytes(), "");
  }

  @AfterEach
  void close() {
    db.close();
  }

  AccessPolicy policy(
      boolean view,
      Integer views,
      boolean download,
      Integer downloads,
      boolean reshare,
      boolean otp) {
    return new AccessPolicy(
        view, views, download, downloads, reshare, null, null, null, null, otp, null);
  }

  long grant(long user) {
    return db.tx(
        s ->
            s.createQuery(
                    "from FilePermission where file.id=:file and recipient.id=:user",
                    FilePermission.class)
                .setParameter("file", file)
                .setParameter("user", user)
                .getSingleResult()
                .id);
  }

  int downloads(long user) {
    return db.tx(s -> s.find(FilePermission.class, grant(user)).downloadsUsed);
  }

  String code(String challenge) {
    String text =
        advanced.localMessages(bala).stream()
            .filter(t -> t.contains(challenge))
            .findFirst()
            .orElseThrow();
    Matcher m = Pattern.compile("code is ([0-9]{6})").matcher(text);
    assertTrue(m.find());
    return m.group(1);
  }

  @Test
  void downloadDisabledExhaustionAndPolicyEditsPreserveCounts() {
    advanced.share(
        anu, file, "bala@test.example", policy(true, 1, false, null, false, false), null);
    assertEquals(
        "The file owner has disabled downloads.",
        assertThrows(AppException.class, () -> app.download(bala, file)).getMessage());
    advanced.share(
        anu, file, "bala@test.example", policy(false, null, true, 1, false, false), null);
    assertNotNull(app.download(bala, file));
    assertTrue(
        assertThrows(AppException.class, () -> app.download(bala, file))
            .getMessage()
            .contains("download limit"));
    advanced.share(
        anu, file, "bala@test.example", policy(false, null, true, 2, false, false), null);
    assertEquals(1, downloads(bala));
    app.download(bala, file);
    assertThrows(
        AppException.class,
        () ->
            advanced.share(
                anu, file, "bala@test.example", policy(false, null, true, 1, false, false), null));
  }

  @Test
  void concurrentFinalTransferOnlyOneStarts() throws Exception {
    advanced.share(
        anu, file, "bala@test.example", policy(false, null, true, 1, false, false), null);
    assertOne(
        () -> {
          try {
            app.download(bala, file);
            return true;
          } catch (AppException e) {
            return false;
          }
        });
    assertEquals(1, downloads(bala));
  }

  void assertOne(Callable<Boolean> job) throws Exception {
    var pool = Executors.newFixedThreadPool(2);
    var start = new CountDownLatch(1);
    Callable<Boolean> work =
        () -> {
          start.await();
          return job.call();
        };
    try {
      var a = pool.submit(work);
      var b = pool.submit(work);
      start.countDown();
      assertNotEquals(a.get(20, TimeUnit.SECONDS), b.get(20, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void viewOnceRefreshDuplicateInitiationClosureAndTimeout() {
    advanced.share(
        anu, file, "bala@test.example", policy(true, 1, false, null, false, false), null);
    var ticket = advanced.openView(bala, file, "initiation_one_123", null);
    var again = advanced.openView(bala, file, "initiation_one_123", null);
    assertEquals(ticket.id(), again.id());
    assertEquals(ticket.id(), advanced.openView(bala, file, "another_tab_12345", null).id());
    assertTrue(advanced.viewPage(bala, ticket.id(), ticket.token(), 0).length > 0);
    advanced.closeView(bala, ticket.id(), ticket.token());
    assertThrows(
        AppException.class, () -> advanced.openView(bala, file, "new_attempt_12345", null));
    assertEquals(1, db.tx(s -> s.find(FilePermission.class, grant(bala)).viewsUsed).intValue());
  }

  @Test
  void expiredOrRevokedViewerCannotServeResources() {
    advanced.share(
        anu, file, "bala@test.example", policy(true, 2, false, null, false, false), null);
    var first = advanced.openView(bala, file, "initiation_one_123", null);
    clock.now = clock.now.plusSeconds(600);
    assertThrows(AppException.class, () -> advanced.viewPage(bala, first.id(), first.token(), 0));
    var second = advanced.openView(bala, file, "initiation_two_123", null);
    advanced.revoke(anu, file, grant(bala));
    assertThrows(AppException.class, () -> advanced.viewPage(bala, second.id(), second.token(), 0));
  }

  @Test
  void delegatedBudgetsCyclesDepthAndCascadingRevocation() throws Exception {
    advanced.share(anu, file, "bala@test.example", policy(true, 2, true, 1, true, false), null);
    advanced.share(
        bala, file, "chitra@test.example", policy(true, 2, true, null, true, false), null);
    advanced.share(
        chitra, file, "devi@test.example", policy(true, 2, true, null, false, false), null);
    assertThrows(
        AppException.class,
        () ->
            advanced.share(
                devi,
                file,
                "bala@test.example",
                policy(false, null, true, null, false, false),
                null));
    assertOne(
        () -> {
          try {
            app.download(
                Thread.currentThread().getName().hashCode() % 2 == 0 ? chitra : devi, file);
            return true;
          } catch (AppException e) {
            return false;
          }
        });
    assertEquals(1, downloads(bala));
    advanced.revoke(anu, file, grant(bala));
    assertThrows(AppException.class, () -> advanced.info(chitra, file));
    assertThrows(AppException.class, () -> advanced.info(devi, file));
  }

  @Test
  void reshareDeniedExactMessageAndAncestorExpiry() {
    app.share(anu, file, "bala@test.example", null);
    assertEquals(
        "This file cannot be shared. The file owner has denied resharing permission.",
        assertThrows(AppException.class, () -> advanced.policyInfo(bala, file)).getMessage());
    AccessPolicy parent =
        new AccessPolicy(
            true, null, true, null, true, clock.now.plusSeconds(60), null, null, null, false, null);
    advanced.share(anu, file, "bala@test.example", parent, null);
    assertThrows(
        AppException.class,
        () ->
            advanced.share(
                bala,
                file,
                "chitra@test.example",
                policy(true, null, true, null, false, false),
                null));
    advanced.share(
        bala,
        file,
        "chitra@test.example",
        new AccessPolicy(
            true,
            null,
            true,
            null,
            false,
            clock.now.plusSeconds(59),
            null,
            null,
            null,
            false,
            null),
        null);
    clock.now = clock.now.plusSeconds(59);
    assertThrows(AppException.class, () -> advanced.info(chitra, file));
  }

  @Test
  void accessCatalogueRequestsAuthorizationAndTransitions() {
    assertTrue(advanced.catalogue(bala, 0).isEmpty());
    assertThrows(AppException.class, () -> advanced.request(bala, file, "Need report"));
    advanced.settings(anu, file, true, "NORMAL");
    advanced.request(bala, file, "Need report");
    assertThrows(AppException.class, () -> advanced.request(bala, file, "Again"));
    long request = (Long) advanced.requests(bala, false, 0).get(0).get("id");
    assertThrows(AppException.class, () -> advanced.approval(chitra, request));
    assertThrows(AppException.class, () -> advanced.decideRequest(chitra, request, "REJECTED", ""));
    advanced.share(
        anu, file, "bala@test.example", policy(true, 1, false, null, false, false), request);
    assertEquals("APPROVED", advanced.requests(bala, false, 0).get(0).get("status"));
    assertThrows(AppException.class, () -> app.download(bala, file));
    assertFalse(advanced.notices(anu, 0).isEmpty());
    assertThrows(AppException.class, () -> advanced.decideRequest(bala, request, "CANCELLED", ""));
  }

  @Test
  void requestRejectionAndCancellation() {
    advanced.settings(anu, file, true, "NORMAL");
    advanced.request(bala, file, "Need report");
    long first = (Long) advanced.requests(bala, false, 0).get(0).get("id");
    advanced.decideRequest(anu, first, "REJECTED", "Not required");
    advanced.request(bala, file, "Another reason");
    long second = (Long) advanced.requests(bala, false, 0).get(0).get("id");
    advanced.decideRequest(bala, second, "CANCELLED", "");
    assertEquals("CANCELLED", advanced.requests(bala, false, 0).get(0).get("status"));
  }

  @Test
  void otpWrongAttemptsExpiryBindingReplayAndRevocation() {
    advanced.share(anu, file, "bala@test.example", policy(true, null, true, 2, false, true), null);
    assertEquals(428, assertThrows(AppException.class, () -> app.download(bala, file)).status);
    String challenge = advanced.startOtp(bala, file, "DOWNLOAD"), otp = code(challenge);
    assertThrows(AppException.class, () -> advanced.verifyOtp(chitra, challenge, otp));
    assertThrows(
        AppException.class,
        () -> advanced.verifyOtp(bala, challenge, otp.equals("000000") ? "111111" : "000000"));
    String permit = advanced.verifyOtp(bala, challenge, otp);
    assertThrows(AppException.class, () -> advanced.verifyOtp(bala, challenge, otp));
    assertNotNull(advanced.download(bala, file, permit, false));
    assertThrows(AppException.class, () -> advanced.download(bala, file, permit, false));
    clock.now = clock.now.plusSeconds(60);
    String next = advanced.startOtp(bala, file, "VIEW");
    String nextCode = code(next);
    clock.now = clock.now.plusSeconds(300);
    assertThrows(AppException.class, () -> advanced.verifyOtp(bala, next, nextCode));
    clock.now = clock.now.plusSeconds(60);
    String third = advanced.startOtp(bala, file, "DOWNLOAD");
    String thirdPermit = advanced.verifyOtp(bala, third, code(third));
    advanced.revoke(anu, file, grant(bala));
    assertThrows(AppException.class, () -> advanced.download(bala, file, thirdPermit, false));
  }

  @Test
  void otpAttemptLimitCooldownAndDeliveryFailure() throws Exception {
    advanced.share(
        anu, file, "bala@test.example", policy(false, null, true, null, false, true), null);
    String challenge = advanced.startOtp(bala, file, "DOWNLOAD"), real = code(challenge);
    for (int i = 0; i < 5; i++)
      assertThrows(
          AppException.class,
          () -> advanced.verifyOtp(bala, challenge, real.equals("000000") ? "111111" : "000000"));
    assertThrows(AppException.class, () -> advanced.verifyOtp(bala, challenge, real));
    assertEquals(
        429,
        assertThrows(AppException.class, () -> advanced.startOtp(bala, file, "DOWNLOAD")).status);
    clock.now = clock.now.plusSeconds(61);
    var cfg = AdvancedConfig.testing(root);
    var failed =
        new AdvancedService(
            db,
            new FileStorage(root),
            new Crypto(CryptoTest.key(1)),
            clock,
            104857600,
            cfg,
            new OtpDelivery(cfg) {
              @Override
              public void send(long u, String e, String c, String value) throws Exception {
                throw new java.io.IOException("SMTP unavailable");
              }
            });
    assertEquals(
        503,
        assertThrows(AppException.class, () -> failed.startOtp(bala, file, "DOWNLOAD")).status);
  }

  @Test
  void versionsPinViewersAndNeverResetBudgets() {
    advanced.share(anu, file, "bala@test.example", policy(true, 2, true, 2, false, false), null);
    var ticket = advanced.openView(bala, file, "view_version_one12", null);
    app.download(bala, file);
    String next = advanced.newVersion(anu, file, "report.txt", "Private version two".getBytes());
    assertEquals(next, advanced.info(bala, file).get("versionId"));
    assertEquals(file, advanced.viewInfo(bala, ticket.id(), ticket.token()).versionId());
    assertEquals(1, downloads(bala));
    advanced.archive(anu, file, file);
    assertThrows(AppException.class, () -> advanced.viewPage(bala, ticket.id(), ticket.token(), 0));
    app.download(bala, file);
    assertThrows(AppException.class, () -> app.download(bala, file));
  }

  @Test
  void alertsThresholdDedupAndOwnerPrivacy() {
    for (int i = 0; i < 10; i++)
      assertThrows(AppException.class, () -> app.download(bala, UUID.randomUUID().toString()));
    List<Map<String, Object>> alerts = advanced.alerts(admin, true, 0);
    assertTrue(alerts.stream().anyMatch(a -> a.get("rule").equals("DISTINCT_IDS")));
    int size = alerts.size();
    assertThrows(AppException.class, () -> app.download(bala, UUID.randomUUID().toString()));
    assertEquals(size, advanced.alerts(admin, true, 0).size());
    assertTrue(advanced.alerts(anu, false, 0).isEmpty());
    long id = (Long) alerts.get(0).get("id");
    advanced.reviewAlert(admin, id, "ACKNOWLEDGED");
    assertThrows(AppException.class, () -> advanced.reviewAlert(anu, id, "RESOLVED"));
  }

  @Test
  void auditCheckpointDetectsAlterationAndTruncation() {
    assertEquals(true, advanced.audit().verify().get("valid"));
    advanced.checkpoint(admin);
    Long sequence =
        db.tx(
            s -> s.createQuery("select max(sequence) from AuditLog", Long.class).getSingleResult());
    db.tx(
        s -> {
          AuditLog a =
              s.createQuery("from AuditLog where sequence=:seq", AuditLog.class)
                  .setParameter("seq", sequence)
                  .getSingleResult();
          a.reason = "ALTERED";
          return null;
        });
    assertEquals(false, advanced.audit().verify().get("valid"));
  }

  @Test
  void rangeAndCorruptFileDoNotConsumeAllowance() throws Exception {
    advanced.share(
        anu, file, "bala@test.example", policy(false, null, true, 1, false, false), null);
    assertEquals(
        416,
        assertThrows(AppException.class, () -> advanced.download(bala, file, null, true)).status);
    String key = db.tx(s -> s.find(FileVersion.class, file).storageKey);
    Path path = root.resolve(key + ".bin");
    byte[] bytes = Files.readAllBytes(path);
    bytes[0] ^= 1;
    Files.write(path, bytes);
    assertThrows(AppException.class, () -> app.download(bala, file));
    assertEquals(0, downloads(bala));
  }
}
