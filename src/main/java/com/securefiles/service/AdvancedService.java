package com.securefiles.service;

import com.securefiles.config.AdvancedConfig;
import com.securefiles.dto.Download;
import com.securefiles.entity.*;
import com.securefiles.exception.AppException;
import com.securefiles.repository.Database;
import com.securefiles.security.*;
import com.securefiles.service.PermissionEngine.Access;
import jakarta.persistence.LockModeType;
import java.io.IOException;
import java.time.*;
import java.util.*;
import java.util.function.Supplier;
import org.hibernate.Session;

public final class AdvancedService {
  private final Database db;
  private final FileStorage storage;
  private final Crypto crypto;
  private final Clock clock;
  private final long quota;
  private final AdvancedConfig config;
  private final PermissionEngine permissions;
  private final AuditTrail audit;
  private final DocumentRenderer renderer = new DocumentRenderer();
  private final OtpDelivery delivery;

  public AdvancedService(
      Database db,
      FileStorage storage,
      Crypto crypto,
      Clock clock,
      long quota,
      AdvancedConfig config) {
    this(db, storage, crypto, clock, quota, config, new OtpDelivery(config));
  }

  public AdvancedService(
      Database db,
      FileStorage storage,
      Crypto crypto,
      Clock clock,
      long quota,
      AdvancedConfig config,
      OtpDelivery delivery) {
    this.db = db;
    this.storage = storage;
    this.crypto = crypto;
    this.clock = clock;
    this.quota = quota;
    this.config = config;
    this.delivery = delivery;
    permissions = new PermissionEngine(clock);
    audit = new AuditTrail(db, clock, config);
  }

  public AuditTrail audit() {
    return audit;
  }

  public PermissionEngine permissions() {
    return permissions;
  }

  private String text(String value, int max) {
    String result = value == null ? "" : value.strip();
    if (result.length() > max
        || result.codePoints().anyMatch(c -> Character.isISOControl(c) && c != 10 && c != 13))
      throw AppException.invalid("Text is invalid or too long.");
    return result;
  }

  private int offset(int page) {
    if (page < 0 || page > 100000) throw AppException.invalid("Invalid page.");
    return page * 20;
  }

  private <T> T guarded(long actor, String file, String action, Supplier<T> work) {
    try {
      return work.get();
    } catch (AppException e) {
      denied(actor, file, action, e.status == 428 ? "OTP_REQUIRED" : "POLICY_DENIED");
      throw e;
    }
  }

  public void denied(long actor, String fileId, String action, String reason) {
    db.tx(
        s -> {
          User user = s.find(User.class, actor);
          StoredFile f = fileId == null ? null : s.find(StoredFile.class, fileId);
          if (f != null
              && !f.owner.getId().equals(actor)
              && s.createQuery(
                          "select count(p) from FilePermission p where p.file.id=:file and"
                              + " p.recipient.id=:id",
                          Long.class)
                      .setParameter("file", fileId)
                      .setParameter("id", actor)
                      .getSingleResult()
                  == 0) f = null;
          audit.append(s, user, action, f, "DENIED", reason, null, fileId);
          return null;
        });
  }

  public void captureInitialVersion(Session s, StoredFile f) {
    FileVersion v = new FileVersion();
    v.id = f.id;
    v.fileId = f.id;
    v.number = 1;
    v.cryptoId = f.id;
    v.storageKey = f.storageKey;
    v.originalName = f.originalName;
    v.mime = f.mime;
    v.size = f.size;
    v.wrappedKey = f.wrappedKey;
    v.wrappingIv = f.wrappingIv;
    v.fileIv = f.fileIv;
    v.createdAt = f.createdAt;
    v.status = f.status;
    v.cryptoVersion = f.cryptoVersion;
    s.persist(v);
    f.currentVersion = v.id;
  }

  public long used(Session s, long actor) {
    return s.createQuery(
            "select coalesce(sum(v.size),0) from FileVersion v, StoredFile f where v.fileId=f.id"
                + " and f.owner.id=:actor and f.status='ACTIVE' and v.status<>'DELETED'",
            Long.class)
        .setParameter("actor", actor)
        .getSingleResult();
  }

  private byte[] decrypt(FileVersion v) {
    if (v.cryptoVersion != 1) throw AppException.unavailable();
    try {
      return crypto.decrypt(
          v.cryptoId,
          new Crypto.Encrypted(storage.read(v.storageKey), v.wrappedKey, v.wrappingIv, v.fileIv));
    } catch (Exception e) {
      throw AppException.unavailable();
    }
  }

  private String watermark(Access a, String reference, Instant time) {
    return a.actor().name + "\n" + a.actor().email + "\nUTC " + time + "\nReference " + reference;
  }

  public Map<String, Object> info(long actor, String fileId) {
    return guarded(
        actor,
        fileId,
        "ACCESS",
        () -> db.tx(s -> info(permissions.resolve(s, actor, fileId, "INFO", null, false, false))));
  }

  public Map<String, Object> policyInfo(long actor, String fileId) {
    return guarded(
        actor,
        fileId,
        "RESHARE",
        () ->
            db.tx(s -> info(permissions.resolve(s, actor, fileId, "RESHARE", null, false, false))));
  }

  private Map<String, Object> info(Access a) {
    Map<String, Object> map = new HashMap<>();
    map.put("id", a.file().id);
    map.put("name", a.content().originalName);
    map.put("versionId", a.content().id);
    map.put("versionNumber", a.content().number);
    map.put("classification", a.file().classification);
    map.put("owner", a.file().owner.getName());
    map.put("otp", a.otp());
    map.put(
        "accessOpen",
        a.chain().stream()
            .allMatch(
                p ->
                    AccessPolicy.inWindow(
                        clock.instant(), p.windowStart, p.windowEnd, p.windowZone)));
    map.put(
        "accessHours",
        a.chain().stream()
            .filter(p -> p.windowStart != null)
            .map(
                p ->
                    String.format(
                        "%02d:%02d–%02d:%02d %s",
                        p.windowStart / 60,
                        p.windowStart % 60,
                        p.windowEnd / 60,
                        p.windowEnd % 60,
                        p.windowZone))
            .collect(java.util.stream.Collectors.joining(" AND ")));
    map.put("viewAllowed", a.chain().stream().allMatch(p -> p.viewAllowed));
    map.put("downloadAllowed", a.chain().stream().allMatch(p -> p.downloadAllowed));
    map.put("reshareAllowed", a.chain().stream().allMatch(p -> p.reshareAllowed));
    map.put("viewsRemaining", permissions.remaining(a, true));
    map.put("downloadsRemaining", permissions.remaining(a, false));
    map.put(
        "expiresAt",
        a.chain().stream()
            .map(p -> p.expiresAt)
            .filter(Objects::nonNull)
            .min(Comparator.naturalOrder())
            .map(Instant::toString)
            .orElse("No expiry"));
    return map;
  }

  public List<Map<String, Object>> sharedFiles(long actor, String search, int page) {
    return db.tx(
        s -> {
          permissions.active(s, actor);
          String q = text(search, 100).toLowerCase(Locale.ROOT);
          List<Map<String, Object>> result = new ArrayList<>();
          for (FilePermission p :
              s.createQuery(
                      "from FilePermission p where p.recipient.id=:actor and p.revokedAt is null"
                          + " and (p.expiresAt is null or p.expiresAt>:now) and"
                          + " p.file.status='ACTIVE' and p.file.owner.active=true and (:q is null"
                          + " or locate(:q,lower(p.file.originalName))>0) order by p.grantedAt"
                          + " desc",
                      FilePermission.class)
                  .setParameter("actor", actor)
                  .setParameter("now", clock.instant())
                  .setParameter("q", q)
                  .setFirstResult(offset(page))
                  .setMaxResults(20)
                  .list())
            try {
              Access a = permissions.resolve(s, actor, p.file.getId(), "LIST", null, false, false);
              Map<String, Object> m = info(a);
              m.put("description", a.file().description == null ? "" : a.file().description);
              m.put("size", a.content().size);
              m.put("createdAt", a.content().createdAt.toString());
              result.add(m);
            } catch (AppException ignored) {
            }
          return result;
        });
  }

  public void checkDownload(long actor, String fileId) {
    guarded(
        actor,
        fileId,
        "DOWNLOAD",
        () ->
            db.tx(
                s -> {
                  permissions.resolve(s, actor, fileId, "DOWNLOAD", null, false, false);
                  return null;
                }));
  }

  public Download download(long actor, String fileId, String permit, boolean range) {
    if (range)
      throw new AppException(
          416, "Range and resume requests are not supported. Start a new transfer.");
    return guarded(
        actor,
        fileId,
        "DOWNLOAD",
        () -> {
          Access prepared =
              db.tx(s -> permissions.resolve(s, actor, fileId, "DOWNLOAD", null, true, false));
          byte[] plain = decrypt(prepared.content());
          String reference = UUID.randomUUID().toString();
          Instant started = clock.instant();
          byte[] output = plain;
          try {
            if (prepared.content().mime.equals("application/pdf"))
              output = renderer.watermark(plain, watermark(prepared, reference, started));
            byte[] ready = output;
            return db.tx(
                s -> {
                  Access current =
                      permissions.resolve(
                          s, actor, fileId, "DOWNLOAD", prepared.content().id, true, true);
                  if (prepared.grant() != null
                      && !Objects.equals(prepared.grant().id, current.grant().id))
                    throw AppException.unavailable();
                  usePermit(s, current, "DOWNLOAD", permit);
                  permissions.consume(current, "DOWNLOAD");
                  audit.append(
                      s,
                      current.actor(),
                      "DOWNLOAD",
                      current.file(),
                      "SUCCESS",
                      reference,
                      current.content().id,
                      null);
                  return new Download(fileId, current.content().originalName, ready);
                });
          } catch (RuntimeException e) {
            if (output != plain) Arrays.fill(output, (byte) 0);
            throw e;
          } finally {
            if (output != plain) Arrays.fill(plain, (byte) 0);
          }
        });
  }

  private void usePermit(Session s, Access a, String action, String token) {
    if (!a.otp()) return;
    OperationPermit permit =
        token == null
            ? null
            : s.find(
                OperationPermit.class, Authenticators.hash(token), LockModeType.PESSIMISTIC_WRITE);
    if (permit == null
        || permit.usedAt != null
        || permit.userId != a.actor().id
        || !permit.fileId.equals(a.file().id)
        || !permit.versionId.equals(a.content().id)
        || !Objects.equals(permit.grantId, a.grant() == null ? null : a.grant().id)
        || !permit.operation.equals(action)
        || !clock.instant().isBefore(permit.expiresAt))
      throw new AppException(428, "Verify a new OTP before this operation.");
    permit.usedAt = clock.instant();
  }

  public String startOtp(long actor, String fileId, String action) {
    if (!Set.of("VIEW", "DOWNLOAD").contains(action))
      throw AppException.invalid("Invalid operation.");
    return guarded(
        actor,
        fileId,
        action,
        () -> {
          String code = Authenticators.otp();
          OtpChallenge c =
              db.tx(
                  s -> {
                    Access a = permissions.resolve(s, actor, fileId, action, null, true, true);
                    List<OtpChallenge> recent =
                        s.createQuery(
                                "from OtpChallenge where userId=:user and createdAt>:since order by"
                                    + " createdAt desc",
                                OtpChallenge.class)
                            .setParameter("user", actor)
                            .setParameter("since", clock.instant().minusSeconds(600))
                            .list();
                    if (recent.size() >= 5
                        || !recent.isEmpty()
                            && clock.instant().isBefore(recent.get(0).createdAt.plusSeconds(60)))
                      throw new AppException(
                          429,
                          "Wait at least 60 seconds before requesting another code. Limit: five"
                              + " codes in ten minutes.");
                    for (OtpChallenge old : recent)
                      if (old.fileId.equals(fileId)
                          && old.operation.equals(action)
                          && old.consumedAt == null) old.consumedAt = clock.instant();
                    OtpChallenge challenge = new OtpChallenge();
                    challenge.id = UUID.randomUUID().toString();
                    challenge.userId = actor;
                    challenge.fileId = fileId;
                    challenge.versionId = a.content().id;
                    challenge.grantId = a.grant() == null ? null : a.grant().id;
                    challenge.operation = action;
                    challenge.createdAt = clock.instant();
                    challenge.expiresAt = clock.instant().plusSeconds(300);
                    challenge.verifier =
                        Authenticators.hmac(config.otpSecret(), otpBinding(challenge, code));
                    s.persist(challenge);
                    audit.append(
                        s,
                        a.actor(),
                        "OTP_ISSUED",
                        a.file(),
                        "SUCCESS",
                        "CHALLENGE_CREATED",
                        a.content().id,
                        null);
                    return challenge;
                  });
          String email = db.tx(s -> permissions.active(s, actor).email);
          try {
            delivery.send(actor, email, c.id, code);
            db.tx(
                s -> {
                  s.find(OtpChallenge.class, c.id).delivered = true;
                  return null;
                });
          } catch (Exception e) {
            db.tx(
                s -> {
                  OtpChallenge failed = s.find(OtpChallenge.class, c.id);
                  failed.consumedAt = clock.instant();
                  audit.append(
                      s,
                      permissions.active(s, actor),
                      "OTP_DELIVERY",
                      s.find(StoredFile.class, fileId),
                      "DENIED",
                      "DELIVERY_FAILED",
                      c.versionId,
                      null);
                  return null;
                });
            throw new AppException(
                503,
                "The verification code could not be delivered. Check delivery settings and retry"
                    + " after the cooldown.");
          }
          return c.id;
        });
  }

  private String otpBinding(OtpChallenge c, String code) {
    return c.id
        + "|"
        + c.userId
        + "|"
        + c.fileId
        + "|"
        + c.versionId
        + "|"
        + c.grantId
        + "|"
        + c.operation
        + "|"
        + code;
  }

  public Map<String, Object> otpInfo(long actor, String challenge) {
    return db.tx(
        s -> {
          permissions.active(s, actor);
          OtpChallenge c = s.find(OtpChallenge.class, challenge);
          if (c == null || c.userId != actor) throw AppException.unavailable();
          return Map.of(
              "id",
              c.id,
              "fileId",
              c.fileId,
              "operation",
              c.operation,
              "expiresAt",
              c.expiresAt.toString(),
              "remaining",
              Math.max(0, 5 - c.attempts),
              "mode",
              config.mailMode());
        });
  }

  public String verifyOtp(long actor, String challenge, String code) {
    String result =
        db.tx(
            s -> {
              permissions.active(s, actor);
              OtpChallenge c =
                  s.find(OtpChallenge.class, challenge, LockModeType.PESSIMISTIC_WRITE);
              if (c == null || c.userId != actor) throw AppException.unavailable();
              if (c.consumedAt != null
                  || c.attempts >= 5
                  || !c.delivered
                  || !clock.instant().isBefore(c.expiresAt)) {
                audit.append(
                    s,
                    permissions.active(s, actor),
                    "OTP_VERIFY",
                    s.find(StoredFile.class, c.fileId),
                    "DENIED",
                    "EXPIRED_REPLAY_OR_LOCKED",
                    c.versionId,
                    null);
                return null;
              }
              c.attempts++;
              boolean valid =
                  code != null
                      && code.matches("[0-9]{6}")
                      && Authenticators.equal(
                          c.verifier, Authenticators.hmac(config.otpSecret(), otpBinding(c, code)));
              audit.append(
                  s,
                  permissions.active(s, actor),
                  "OTP_VERIFY",
                  s.find(StoredFile.class, c.fileId),
                  valid ? "SUCCESS" : "DENIED",
                  valid ? "VERIFIED" : "INVALID_CODE",
                  c.versionId,
                  null);
              if (!valid) return null;
              Access a =
                  permissions.resolve(s, actor, c.fileId, c.operation, c.versionId, true, false);
              if (!Objects.equals(c.grantId, a.grant() == null ? null : a.grant().id)) return null;
              c.consumedAt = clock.instant();
              String token = Authenticators.randomToken();
              OperationPermit p = new OperationPermit();
              p.id = Authenticators.hash(token);
              p.userId = actor;
              p.fileId = c.fileId;
              p.versionId = c.versionId;
              p.grantId = c.grantId;
              p.operation = c.operation;
              p.expiresAt = clock.instant().plusSeconds(120);
              s.persist(p);
              return token;
            });
    if (result == null)
      throw new AppException(
          403, "The code is invalid, expired or already used. Five attempts are allowed.");
    return result;
  }

  public List<String> localMessages(long actor) {
    db.tx(
        s -> {
          permissions.active(s, actor);
          return null;
        });
    return delivery.localMessages(actor);
  }

  public record ViewTicket(
      String id,
      String token,
      String fileId,
      String name,
      String versionId,
      int pages,
      String expiresAt) {}

  private ViewTicket ticket(ViewingSession v, String name) {
    return new ViewTicket(
        v.id,
        Authenticators.hmac(config.otpSecret(), "viewer|" + v.id + "|" + v.userId),
        v.fileId,
        name,
        v.versionId,
        v.pageCount,
        v.expiresAt.toString());
  }

  public ViewTicket openView(long actor, String fileId, String initiation, String permit) {
    String clean = text(initiation, 80);
    if (!clean.matches("[A-Za-z0-9_-]{16,80}"))
      throw AppException.invalid("Invalid viewing initiation. Reload the page.");
    return guarded(
        actor,
        fileId,
        "VIEW",
        () -> {
          Access prepared =
              db.tx(s -> permissions.resolve(s, actor, fileId, "VIEW", null, false, false));
          byte[] bytes = decrypt(prepared.content());
          DocumentRenderer.Rendered first;
          try {
            first =
                renderer.page(
                    prepared.content().mime,
                    bytes,
                    0,
                    watermark(prepared, "Viewing session", clock.instant()));
          } finally {
            Arrays.fill(bytes, (byte) 0);
          }
          Arrays.fill(first.bytes(), (byte) 0);
          return db.tx(
              s -> {
                Access a =
                    permissions.resolve(
                        s, actor, fileId, "VIEW", prepared.content().id, false, true);
                ViewingSession old =
                    s.createQuery(
                            "from ViewingSession where initiationKey=:key", ViewingSession.class)
                        .setParameter("key", actor + ":" + clean)
                        .uniqueResult();
                if (old != null) {
                  if (!old.fileId.equals(fileId)
                      || a.otp() && !old.otpVerified
                      || old.closedAt != null
                      || !clock.instant().isBefore(old.expiresAt))
                    throw new AppException(
                        403,
                        "This viewing session has ended. Start a new initiation from the file"
                            + " page.");
                  return ticket(old, a.content().originalName);
                }
                List<ViewingSession> active =
                    s.createQuery(
                            "from ViewingSession where userId=:user and fileId=:file and"
                                + " versionId=:version and closedAt is null and expiresAt>:now"
                                + " order by createdAt desc",
                            ViewingSession.class)
                        .setParameter("user", actor)
                        .setParameter("file", fileId)
                        .setParameter("version", a.content().id)
                        .setParameter("now", clock.instant())
                        .list();
                if (!active.isEmpty()
                    && Objects.equals(
                        active.get(0).grantId, a.grant() == null ? null : a.grant().id)
                    && (!a.otp() || active.get(0).otpVerified))
                  return ticket(active.get(0), a.content().originalName);
                a =
                    permissions.resolve(
                        s, actor, fileId, "VIEW", prepared.content().id, true, true);
                usePermit(s, a, "VIEW", permit);
                permissions.consume(a, "VIEW");
                ViewingSession v = new ViewingSession();
                v.id = UUID.randomUUID().toString();
                v.userId = actor;
                v.fileId = fileId;
                v.versionId = a.content().id;
                v.grantId = a.grant() == null ? null : a.grant().id;
                v.initiationKey = actor + ":" + clean;
                v.createdAt = clock.instant();
                v.expiresAt = clock.instant().plusSeconds(600);
                v.pageCount = first.pages();
                v.otpVerified = a.otp();
                s.persist(v);
                audit.append(
                    s,
                    a.actor(),
                    "VIEW_SESSION",
                    a.file(),
                    "SUCCESS",
                    "SESSION_CREATED",
                    v.versionId,
                    null);
                return ticket(v, a.content().originalName);
              });
        });
  }

  private ViewingSession session(Session s, long actor, String id, String token) {
    permissions.active(s, actor);
    ViewingSession v = id == null ? null : s.find(ViewingSession.class, id);
    if (v == null
        || v.userId != actor
        || v.closedAt != null
        || !clock.instant().isBefore(v.expiresAt)
        || !Authenticators.equal(ticket(v, "").token(), token))
      throw new AppException(403, "This viewing session has ended.");
    Access a = permissions.resolve(s, actor, v.fileId, "VIEW", v.versionId, false, false);
    if (a.otp() && !v.otpVerified)
      throw new AppException(428, "This viewer now requires a new OTP-authorized session.");
    if (!Objects.equals(v.grantId, a.grant() == null ? null : a.grant().id))
      throw AppException.unavailable();
    return v;
  }

  public ViewTicket viewInfo(long actor, String id, String token) {
    return db.tx(
        s -> {
          ViewingSession v = session(s, actor, id, token);
          return ticket(v, s.find(FileVersion.class, v.versionId).originalName);
        });
  }

  public byte[] viewPage(long actor, String id, String token, int page) {
    try {
      return viewPageChecked(actor, id, token, page);
    } catch (AppException e) {
      String fileId =
          db.tx(
              s -> {
                ViewingSession v = id == null ? null : s.find(ViewingSession.class, id);
                return v != null && v.userId == actor ? v.fileId : null;
              });
      denied(actor, fileId, "VIEW_RESOURCE", "POLICY_DENIED");
      throw e;
    }
  }

  private byte[] viewPageChecked(long actor, String id, String token, int page) {
    ViewingSession v = db.tx(s -> session(s, actor, id, token));
    Access a =
        db.tx(s -> permissions.resolve(s, actor, v.fileId, "VIEW", v.versionId, false, false));
    byte[] bytes = decrypt(a.content());
    byte[] rendered;
    try {
      rendered =
          renderer
              .page(
                  a.content().mime,
                  bytes,
                  page,
                  watermark(a, "Session " + v.createdAt, v.createdAt))
              .bytes();
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
    try {
      db.tx(
          s -> {
            session(s, actor, id, token);
            return null;
          });
      return rendered;
    } catch (RuntimeException e) {
      Arrays.fill(rendered, (byte) 0);
      throw e;
    }
  }

  public void closeView(long actor, String id, String token) {
    db.tx(
        s -> {
          ViewingSession v = session(s, actor, id, token);
          v.closedAt = clock.instant();
          audit.append(
              s,
              permissions.active(s, actor),
              "VIEW_CLOSED",
              s.find(StoredFile.class, v.fileId),
              "SUCCESS",
              "CLOSED",
              v.versionId,
              null);
          return null;
        });
  }

  public void share(
      long actor, String fileId, String email, AccessPolicy policy, Long approvalRequest) {
    guarded(
        actor,
        fileId,
        "RESHARE",
        () ->
            db.tx(
                s -> {
                  Access parent =
                      permissions.resolve(s, actor, fileId, "RESHARE", null, false, true);
                  User recipient =
                      s.createQuery("from User where email=:email and active=true", User.class)
                          .setParameter("email", com.securefiles.service.AppService.email(email))
                          .uniqueResult();
                  if (recipient == null)
                    throw AppException.invalid("No active registered user has that email address.");
                  if (recipient.id.equals(actor)
                      || recipient.id.equals(parent.file().owner.getId())
                      || parent.chain().stream()
                          .anyMatch(p -> p.recipient.getId().equals(recipient.id)))
                    throw AppException.invalid(
                        "Sharing with yourself or a grant ancestor is not allowed.");
                  if (parent.chain().size() >= 3)
                    throw AppException.invalid("Delegation is limited to three recipient levels.");
                  if (policy.expiresAt() != null && !clock.instant().isBefore(policy.expiresAt()))
                    throw AppException.invalid("Expiry must be in the future.");
                  if (parent.grant() != null)
                    for (FilePermission ancestor : parent.chain()) {
                      if (policy.viewing() && !ancestor.viewAllowed
                          || policy.downloading() && !ancestor.downloadAllowed
                          || policy.resharing() && !ancestor.reshareAllowed
                          || ancestor.otpRequired && !policy.otp())
                        throw AppException.invalid(
                            "A delegated policy cannot be broader than its parent policy.");
                      if (ancestor.expiresAt != null
                          && (policy.expiresAt() == null
                              || policy.expiresAt().isAfter(ancestor.expiresAt)))
                        throw AppException.invalid(
                            "Child expiry cannot exceed an ancestor's expiry.");
                      if (ancestor.targetVersion != null
                          && !ancestor.targetVersion.equals(policy.targetVersion()))
                        throw AppException.invalid(
                            "Delegated access must retain the ancestor's pinned version.");
                    }
                  if (policy.targetVersion() != null) {
                    FileVersion v = s.find(FileVersion.class, policy.targetVersion());
                    if (v == null || !v.fileId.equals(fileId) || !v.status.equals("ACTIVE"))
                      throw AppException.unavailable();
                  }
                  FilePermission p =
                      s.createQuery(
                              "from FilePermission where file.id=:file and recipient.id=:recipient",
                              FilePermission.class)
                          .setParameter("file", fileId)
                          .setParameter("recipient", recipient.id)
                          .uniqueResult();
                  if (p != null
                      && parent.grant() != null
                      && (!Objects.equals(p.parentId, parent.grant().id)
                          || !p.grantedBy.getId().equals(actor)))
                    throw AppException.invalid(
                        "This user already has a grant. Only the original owner can change its"
                            + " delegation path.");
                  if (p != null
                      && (policy.viewLimit() != null && policy.viewLimit() < p.viewsUsed
                          || policy.downloadLimit() != null
                              && policy.downloadLimit() < p.downloadsUsed))
                    throw AppException.invalid(
                        "The new limit cannot be below its consumed count. Counts are never reset"
                            + " by a policy edit.");
                  if (p == null) {
                    p = new FilePermission();
                    p.file = parent.file();
                    p.recipient = recipient;
                    p.grantedBy = parent.actor();
                  }
                  // An owner cannot graft an ancestor under its existing descendant.
                  if (p.id != null)
                    for (FilePermission ancestor : parent.chain())
                      if (ancestor.id.equals(p.id))
                        throw AppException.invalid("A grant cycle is not allowed.");
                  p.parentId = parent.grant() == null ? null : parent.grant().id;
                  p.grantedBy = parent.actor();
                  p.viewAllowed = policy.viewing();
                  p.viewLimit = policy.viewLimit();
                  p.downloadAllowed = policy.downloading();
                  p.downloadLimit = policy.downloadLimit();
                  p.reshareAllowed = policy.resharing();
                  p.otpRequired = policy.otp();
                  p.expiresAt = policy.expiresAt();
                  p.windowStart = policy.startMinute();
                  p.windowEnd = policy.endMinute();
                  p.windowZone = policy.timezone();
                  p.targetVersion = policy.targetVersion();
                  p.grantedAt = clock.instant();
                  p.revokedAt = null;
                  s.persist(p);
                  if (approvalRequest != null) {
                    AccessRequest request =
                        s.find(
                            AccessRequest.class, approvalRequest, LockModeType.PESSIMISTIC_WRITE);
                    if (!parent.file().owner.getId().equals(actor)
                        || request == null
                        || !request.fileId.equals(fileId)
                        || request.requesterId != recipient.id
                        || !request.status.equals("PENDING")) throw AppException.unavailable();
                    decide(
                        s,
                        request,
                        actor,
                        "APPROVED",
                        "Approved with the displayed access policy.");
                  }
                  audit.append(
                      s,
                      parent.actor(),
                      parent.grant() == null ? "SHARE" : "DELEGATED_SHARE",
                      parent.file(),
                      "SUCCESS",
                      "POLICY_SAVED",
                      policy.targetVersion(),
                      null);
                  notify(s, recipient.id, fileId, "Access settings were granted or updated.");
                  return null;
                }));
  }

  private boolean createdBranch(Session s, long actor, FilePermission target) {
    Set<Long> seen = new HashSet<>();
    FilePermission p = target;
    while (p != null && seen.add(p.id) && seen.size() <= 3) {
      if (p.grantedBy.getId().equals(actor)) return true;
      p = p.parentId == null ? null : s.find(FilePermission.class, p.parentId);
    }
    return false;
  }

  public void revoke(long actor, String fileId, long grantId) {
    guarded(
        actor,
        fileId,
        "REVOKE",
        () ->
            db.tx(
                s -> {
                  permissions.active(s, actor);
                  StoredFile file = permissions.file(s, fileId, true);
                  FilePermission target = s.find(FilePermission.class, grantId);
                  if (target == null || !target.file.getId().equals(fileId))
                    throw AppException.unavailable();
                  if (!file.owner.getId().equals(actor) && !createdBranch(s, actor, target))
                    throw AppException.unavailable();
                  Set<Long> branch = new HashSet<>();
                  branch.add(grantId);
                  List<FilePermission> grants =
                      s.createQuery("from FilePermission where file.id=:file", FilePermission.class)
                          .setParameter("file", fileId)
                          .list();
                  for (int i = 0; i < 3; i++)
                    for (FilePermission p : grants)
                      if (p.parentId != null && branch.contains(p.parentId)) branch.add(p.id);
                  for (FilePermission p : grants)
                    if (branch.contains(p.id)) p.revokedAt = clock.instant();
                  audit.append(
                      s,
                      permissions.active(s, actor),
                      "REVOKE",
                      file,
                      "SUCCESS",
                      "BRANCH_REVOKED",
                      null,
                      null);
                  return null;
                }));
  }

  public List<Map<String, Object>> grants(long actor, String fileId) {
    return db.tx(
        s -> {
          permissions.active(s, actor);
          StoredFile f = permissions.file(s, fileId, false);
          boolean owner = f.owner.getId().equals(actor);
          if (!owner) permissions.resolve(s, actor, fileId, "RESHARE", null, false, false);
          return s
              .createQuery(
                  "from FilePermission where file.id=:file order by id", FilePermission.class)
              .setParameter("file", fileId)
              .list()
              .stream()
              .filter(p -> owner || createdBranch(s, actor, p))
              .map(
                  p -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("id", p.id);
                    m.put("parent", p.parentId == null ? "Owner" : p.parentId);
                    m.put("email", p.recipient.getEmail());
                    m.put("viewAllowed", p.viewAllowed);
                    m.put("downloadAllowed", p.downloadAllowed);
                    m.put("reshareAllowed", p.reshareAllowed);
                    m.put("otp", p.otpRequired);
                    m.put("viewLimit", p.viewLimit == null ? "" : p.viewLimit);
                    m.put("downloadLimit", p.downloadLimit == null ? "" : p.downloadLimit);
                    m.put("viewsUsed", p.viewsUsed);
                    m.put("downloadsUsed", p.downloadsUsed);
                    m.put("expiresAt", p.expiresAt == null ? "" : p.expiresAt.toString());
                    m.put(
                        "state",
                        p.revokedAt != null
                            ? "Revoked"
                            : p.expiresAt != null && !clock.instant().isBefore(p.expiresAt)
                                ? "Expired"
                                : "Active");
                    m.put(
                        "targetVersion",
                        p.targetVersion == null ? "Latest active" : p.targetVersion);
                    m.put("targetValue", p.targetVersion == null ? "" : p.targetVersion);
                    m.put(
                        "expiryInput",
                        p.expiresAt == null ? "" : p.expiresAt.toString().substring(0, 16));
                    m.put(
                        "startInput",
                        p.windowStart == null
                            ? ""
                            : String.format("%02d:%02d", p.windowStart / 60, p.windowStart % 60));
                    m.put(
                        "endInput",
                        p.windowEnd == null
                            ? ""
                            : String.format("%02d:%02d", p.windowEnd / 60, p.windowEnd % 60));
                    m.put("timezone", p.windowZone == null ? "UTC" : p.windowZone);
                    m.put(
                        "hours",
                        p.windowStart == null
                            ? "Any time"
                            : String.format(
                                "%02d:%02d–%02d:%02d %s",
                                p.windowStart / 60,
                                p.windowStart % 60,
                                p.windowEnd / 60,
                                p.windowEnd % 60,
                                p.windowZone));
                    return m;
                  })
              .toList();
        });
  }

  private void notify(Session s, long user, String file, String message) {
    Notification n = new Notification();
    n.userId = user;
    n.fileId = file;
    n.message = message;
    n.createdAt = clock.instant();
    s.persist(n);
  }

  public void settings(long actor, String fileId, boolean listed, String classification) {
    if (!Set.of("NORMAL", "CONFIDENTIAL").contains(classification))
      throw AppException.invalid("Invalid classification.");
    db.tx(
        s -> {
          StoredFile f = permissions.owner(s, actor, fileId, true);
          f.listed = listed;
          f.classification = classification;
          audit.append(
              s,
              permissions.active(s, actor),
              "FILE_SETTINGS",
              f,
              "SUCCESS",
              "CLASSIFICATION_CATALOGUE",
              null,
              null);
          return null;
        });
  }

  public List<Map<String, Object>> catalogue(long actor, int page) {
    return db.tx(
        s -> {
          permissions.active(s, actor);
          return s
              .createQuery(
                  "from StoredFile f where f.listed=true and f.status='ACTIVE' and f.currentVersion"
                      + " is not null and f.owner.active=true and f.owner.id<>:actor order by"
                      + " f.createdAt desc",
                  StoredFile.class)
              .setParameter("actor", actor)
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .list()
              .stream()
              .map(
                  f ->
                      Map.<String, Object>of(
                          "id",
                          f.id,
                          "name",
                          f.originalName,
                          "owner",
                          f.owner.getName(),
                          "description",
                          f.description == null ? "" : f.description))
              .toList();
        });
  }

  public void request(long actor, String fileId, String reason) {
    String clean = text(reason, 500);
    if (clean.isBlank()) throw AppException.invalid("Enter a short reason.");
    db.tx(
        s -> {
          User user = permissions.active(s, actor);
          StoredFile f = permissions.file(s, fileId, true);
          if (!f.listed || f.currentVersion == null || f.owner.getId().equals(actor))
            throw AppException.unavailable();
          String key = fileId + ":" + actor;
          if (s.createQuery(
                      "select count(r) from AccessRequest r where pendingKey=:key", Long.class)
                  .setParameter("key", key)
                  .getSingleResult()
              > 0) throw AppException.invalid("You already have a pending request for this file.");
          AccessRequest r = new AccessRequest();
          r.fileId = fileId;
          r.requesterId = actor;
          r.reason = clean;
          r.pendingKey = key;
          r.createdAt = clock.instant();
          s.persist(r);
          RequestDecision history = new RequestDecision();
          history.requestId = r.id;
          history.actorId = actor;
          history.status = "PENDING";
          history.occurredAt = clock.instant();
          history.note = clean;
          s.persist(history);
          notify(
              s,
              f.owner.getId(),
              fileId,
              "A registered user requested access. Open Requests Received.");
          audit.append(s, user, "ACCESS_REQUEST", f, "SUCCESS", "PENDING", null, null);
          return null;
        });
  }

  private void decide(Session s, AccessRequest r, long actor, String state, String note) {
    r.status = state;
    r.pendingKey = null;
    r.decidedAt = clock.instant();
    r.decisionNote = text(note, 500);
    RequestDecision h = new RequestDecision();
    h.requestId = r.id;
    h.actorId = actor;
    h.status = state;
    h.note = r.decisionNote;
    h.occurredAt = r.decidedAt;
    s.persist(h);
    notify(
        s,
        r.requesterId,
        r.fileId,
        "Your access request is " + state.toLowerCase(Locale.ROOT) + ".");
    audit.append(
        s,
        permissions.active(s, actor),
        "REQUEST_" + state,
        s.find(StoredFile.class, r.fileId),
        "SUCCESS",
        state,
        null,
        null);
  }

  public void decideRequest(long actor, long request, String action, String note) {
    db.tx(
        s -> {
          permissions.active(s, actor);
          AccessRequest r = s.find(AccessRequest.class, request);
          if (r == null) throw AppException.unavailable();
          StoredFile f = permissions.file(s, r.fileId, true);
          s.lock(r, LockModeType.PESSIMISTIC_WRITE);
          if (!r.status.equals("PENDING"))
            throw AppException.invalid("This request has already been decided.");
          if (action.equals("CANCELLED")) {
            if (r.requesterId != actor) throw AppException.unavailable();
          } else if (action.equals("REJECTED")) {
            if (!f.owner.getId().equals(actor)) throw AppException.unavailable();
          } else throw AppException.invalid("Approval requires the access-policy form.");
          decide(s, r, actor, action, note);
          return null;
        });
  }

  public Map<String, Object> approval(long actor, long request) {
    return db.tx(
        s -> {
          AccessRequest r = s.find(AccessRequest.class, request);
          if (r == null || !r.status.equals("PENDING")) throw AppException.unavailable();
          permissions.owner(s, actor, r.fileId, false);
          User u = s.find(User.class, r.requesterId);
          return Map.of(
              "requestId", r.id, "fileId", r.fileId, "email", u.email, "reason", r.reason);
        });
  }

  public List<Map<String, Object>> requests(long actor, boolean received, int page) {
    return db.tx(
        s -> {
          permissions.active(s, actor);
          String hql =
              received
                  ? "select r from AccessRequest r, StoredFile f where r.fileId=f.id and"
                      + " f.owner.id=:actor"
                  : "from AccessRequest r where r.requesterId=:actor";
          return s
              .createQuery(hql + " order by r.createdAt desc, r.id desc", AccessRequest.class)
              .setParameter("actor", actor)
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .list()
              .stream()
              .map(
                  r -> {
                    StoredFile f = s.find(StoredFile.class, r.fileId);
                    return Map.<String, Object>of(
                        "id",
                        r.id,
                        "fileId",
                        r.fileId,
                        "name",
                        f.originalName,
                        "email",
                        s.find(User.class, r.requesterId).email,
                        "reason",
                        r.reason,
                        "status",
                        r.status,
                        "note",
                        r.decisionNote == null ? "" : r.decisionNote,
                        "createdAt",
                        r.createdAt.toString());
                  })
              .toList();
        });
  }

  public String newVersion(long actor, String fileId, String name, byte[] bytes) {
    String mime = new UploadValidator().validate(name, bytes);
    db.tx(
        s -> {
          permissions.owner(s, actor, fileId, false);
          return null;
        });
    String id = UUID.randomUUID().toString(), key = UUID.randomUUID().toString();
    Crypto.Encrypted encrypted;
    try {
      encrypted = crypto.encrypt(id, bytes);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    try {
      return db.tx(
          s -> {
            s.find(User.class, actor, LockModeType.PESSIMISTIC_WRITE);
            StoredFile f = permissions.owner(s, actor, fileId, true);
            if (used(s, actor) + bytes.length > quota)
              throw AppException.invalid("Your storage quota would be exceeded.");
            FileVersion v = new FileVersion();
            v.id = id;
            v.fileId = fileId;
            v.cryptoId = id;
            v.storageKey = key;
            v.originalName = name;
            v.mime = mime;
            v.size = bytes.length;
            v.number =
                s.createQuery(
                            "select max(number) from FileVersion where fileId=:file", Integer.class)
                        .setParameter("file", fileId)
                        .getSingleResult()
                    + 1;
            v.wrappedKey = encrypted.wrappedKey();
            v.wrappingIv = encrypted.wrappingIv();
            v.fileIv = encrypted.fileIv();
            v.createdAt = clock.instant();
            try {
              storage.write(key, encrypted.bytes());
            } catch (IOException e) {
              throw new IllegalStateException("Version write failed", e);
            }
            s.persist(v);
            f.currentVersion = id;
            f.originalName = name;
            f.mime = mime;
            f.size = bytes.length;
            f.updatedAt = clock.instant();
            audit.append(
                s,
                permissions.active(s, actor),
                "VERSION_UPLOAD",
                f,
                "SUCCESS",
                "NEW_IMMUTABLE_VERSION",
                id,
                null);
            return id;
          });
    } catch (RuntimeException e) {
      try {
        if (!db.tx(s -> s.find(FileVersion.class, id) != null)) storage.delete(key);
      } catch (Exception ignored) {
      }
      throw e;
    }
  }

  public List<Map<String, Object>> versions(long actor, String fileId) {
    return versions(actor, fileId, 0);
  }

  public List<Map<String, Object>> versions(long actor, String fileId, int page) {
    return db.tx(
        s -> {
          StoredFile f = permissions.owner(s, actor, fileId, false);
          return s
              .createQuery(
                  "from FileVersion where fileId=:file order by number desc", FileVersion.class)
              .setParameter("file", fileId)
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .list()
              .stream()
              .map(
                  v ->
                      Map.<String, Object>of(
                          "id",
                          v.id,
                          "number",
                          v.number,
                          "name",
                          v.originalName,
                          "size",
                          v.size,
                          "status",
                          v.status,
                          "current",
                          v.id.equals(f.currentVersion),
                          "createdAt",
                          v.createdAt.toString()))
              .toList();
        });
  }

  public void archive(long actor, String fileId, String version) {
    db.tx(
        s -> {
          StoredFile f = permissions.owner(s, actor, fileId, true);
          FileVersion v = s.find(FileVersion.class, version);
          if (v == null || !v.fileId.equals(fileId) || !v.status.equals("ACTIVE"))
            throw AppException.unavailable();
          v.status = "ARCHIVED";
          s.flush();
          List<String> active =
              s.createQuery(
                      "select id from FileVersion where fileId=:file and status='ACTIVE' order by"
                          + " number desc",
                      String.class)
                  .setParameter("file", fileId)
                  .setMaxResults(1)
                  .list();
          f.currentVersion = active.isEmpty() ? null : active.get(0);
          if (f.currentVersion != null) {
            FileVersion current = s.find(FileVersion.class, f.currentVersion);
            f.originalName = current.originalName;
            f.mime = current.mime;
            f.size = current.size;
          }
          f.updatedAt = clock.instant();
          audit.append(
              s,
              permissions.active(s, actor),
              "VERSION_ARCHIVE",
              f,
              "SUCCESS",
              "ARCHIVED",
              version,
              null);
          return null;
        });
  }

  public List<Map<String, Object>> notices(long actor, int page) {
    return db.tx(
        s -> {
          permissions.active(s, actor);
          return s
              .createQuery(
                  "from Notification where userId=:actor order by createdAt desc",
                  Notification.class)
              .setParameter("actor", actor)
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .list()
              .stream()
              .map(
                  n ->
                      Map.<String, Object>of(
                          "id",
                          n.id,
                          "message",
                          n.message,
                          "read",
                          n.readAt != null,
                          "createdAt",
                          n.createdAt.toString()))
              .toList();
        });
  }

  public void readNotice(long actor, long id) {
    db.tx(
        s -> {
          permissions.active(s, actor);
          Notification n = s.find(Notification.class, id);
          if (n == null || n.userId != actor) throw AppException.unavailable();
          n.readAt = clock.instant();
          return null;
        });
  }

  public List<Map<String, Object>> alerts(long actor, boolean admin, int page) {
    return db.tx(
        s -> {
          if (admin) permissions.admin(s, actor);
          else permissions.active(s, actor);
          var query =
              s.createQuery(
                  "from SecurityAlert where "
                      + (admin ? "ownerId is null" : "ownerId=:actor")
                      + " order by createdAt desc",
                  SecurityAlert.class);
          if (!admin) query.setParameter("actor", actor);
          return query.setFirstResult(offset(page)).setMaxResults(20).list().stream()
              .map(
                  a ->
                      Map.<String, Object>of(
                          "id",
                          a.id,
                          "actor",
                          admin ? s.find(User.class, a.actorId).email : "Recipient of your file",
                          "rule",
                          a.rule,
                          "count",
                          a.count,
                          "window",
                          a.windowSeconds,
                          "file",
                          a.fileId == null ? "" : a.fileId,
                          "status",
                          a.status,
                          "createdAt",
                          a.createdAt.toString()))
              .toList();
        });
  }

  public void reviewAlert(long actor, long alert, String state) {
    if (!Set.of("ACKNOWLEDGED", "RESOLVED").contains(state))
      throw AppException.invalid("Invalid alert status.");
    db.tx(
        s -> {
          permissions.admin(s, actor);
          SecurityAlert a = s.find(SecurityAlert.class, alert, LockModeType.PESSIMISTIC_WRITE);
          if (a == null || a.ownerId != null) throw AppException.unavailable();
          a.status = state;
          a.reviewedBy = actor;
          a.reviewedAt = clock.instant();
          audit.append(
              s, permissions.active(s, actor), "ALERT_REVIEW", null, "SUCCESS", state, null, null);
          return null;
        });
  }

  public Map<String, Object> verifyAudit(long actor) {
    db.tx(
        s -> {
          permissions.admin(s, actor);
          return null;
        });
    Map<String, Object> result = audit.verify();
    db.tx(
        s -> {
          audit.append(
              s,
              permissions.active(s, actor),
              "AUDIT_VERIFY",
              null,
              "SUCCESS",
              (boolean) result.get("valid") ? "VALID" : "INCONSISTENCY",
              null,
              null);
          return null;
        });
    return result;
  }

  public Map<String, Object> checkpoint(long actor) {
    db.tx(
        s -> {
          permissions.admin(s, actor);
          return null;
        });
    Map<String, Object> result = audit.checkpoint();
    db.tx(
        s -> {
          audit.append(
              s,
              permissions.active(s, actor),
              "AUDIT_CHECKPOINT",
              null,
              "SUCCESS",
              "EXPORTED",
              null,
              null);
          return null;
        });
    return result;
  }

  public void maintenance() {
    delivery.cleanup(clock.instant().minusSeconds(600));
    audit.checkpoint();
  }

  public void cancelRequestsForDeletion(Session s, StoredFile file, long actor) {
    for (AccessRequest r :
        s.createQuery(
                "from AccessRequest where fileId=:file and status='PENDING'", AccessRequest.class)
            .setParameter("file", file.id)
            .list()) decide(s, r, actor, "CANCELLED", "The owner deleted this file.");
  }

  public List<Map<String, Object>> checkpointList(long actor, int page) {
    return db.tx(
        s -> {
          permissions.admin(s, actor);
          return s
              .createQuery("from AuditCheckpoint order by createdAt desc", AuditCheckpoint.class)
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .list()
              .stream()
              .map(
                  c ->
                      Map.<String, Object>of(
                          "sequence",
                          c.sequence,
                          "hash",
                          c.hash,
                          "createdAt",
                          c.createdAt.toString()))
              .toList();
        });
  }
}
