package com.securefiles.service;

import com.securefiles.dto.Download;
import com.securefiles.entity.*;
import com.securefiles.exception.AppException;
import com.securefiles.repository.Database;
import com.securefiles.security.*;
import jakarta.persistence.LockModeType;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.*;
import java.util.*;
import org.hibernate.Session;

public final class AppService {
  private final Database db;
  private final FileStorage storage;
  private final Crypto crypto;
  private final Clock clock;
  private final long quota;
  private final LoginThrottle throttle;
  private final AdvancedService advanced;
  private final String dummyHash = Passwords.hash("dummy login timing password");

  public AppService(Database db, FileStorage storage, Crypto crypto, Clock clock, long quota) {
    this.db = db;
    this.storage = storage;
    this.crypto = crypto;
    this.clock = clock;
    this.quota = quota;
    throttle = new LoginThrottle(clock);
    advanced =
        new AdvancedService(
            db,
            storage,
            crypto,
            clock,
            quota,
            db.isTest()
                ? com.securefiles.config.AdvancedConfig.testing(storage.root())
                : com.securefiles.config.AdvancedConfig.environment(storage.root()));
  }

  public static String email(String email) {
    String normalized = email == null ? "" : email.strip().toLowerCase(Locale.ROOT);
    if (normalized.length() > 254 || !normalized.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+"))
      throw AppException.invalid("Enter a valid email address.");
    return normalized;
  }

  private String text(String text, int max, String label) {
    String result = text == null ? "" : text.strip();
    if (result.length() > max
        || result.codePoints().anyMatch(c -> Character.isISOControl(c) && c != 10 && c != 13))
      throw AppException.invalid(label + " is invalid or too long.");
    return result;
  }

  public long register(String name, String email, String password, String confirmation) {
    if (!Objects.equals(password, confirmation))
      throw AppException.invalid("The passwords do not match.");
    return createUser(name, email, password, "USER");
  }

  public long bootstrapAdmin(String name, String email, String password) {
    return createUser(name, email, password, "ADMIN");
  }

  private long createUser(String name, String email, String password, String role) {
    String normalized = email(email), cleanName = text(name, 100, "Name");
    if (cleanName.isBlank()) throw AppException.invalid("Enter your name.");
    String hash = Passwords.hash(password);
    try {
      return db.tx(
          s -> {
            if (s.createQuery("from User where email=:email", User.class)
                    .setParameter("email", normalized)
                    .uniqueResult()
                != null) throw AppException.invalid("This email address is already registered.");
            User u = new User();
            u.name = cleanName;
            u.email = normalized;
            u.passwordHash = hash;
            u.role = role;
            u.createdAt = clock.instant();
            s.persist(u);
            audit(s, u, "REGISTER", null, "SUCCESS", "CREATED");
            return u.id;
          });
    } catch (org.hibernate.exception.ConstraintViolationException e) {
      throw AppException.invalid("This email address is already registered.");
    }
  }

  public long login(String email, String password, String ip) {
    String normalized;
    try {
      normalized = email(email);
    } catch (AppException e) {
      normalized = "invalid";
    }
    final String address = normalized;
    String bucket = "email:" + address, remote = "ip:" + ip;
    if (!throttle.allowed(bucket) || !throttle.allowed(remote)) {
      db.tx(
          s -> {
            audit(s, null, "LOGIN", null, "DENIED", "THROTTLED");
            return null;
          });
      throw new AppException(429, "Too many failed attempts. Wait five minutes.");
    }
    Long id =
        db.tx(
            s -> {
              User u =
                  s.createQuery("from User where email=:email", User.class)
                      .setParameter("email", address)
                      .uniqueResult();
              boolean valid = Passwords.verify(u == null ? dummyHash : u.passwordHash, password);
              boolean allowed = valid && u != null && u.active;
              audit(
                  s,
                  u,
                  "LOGIN",
                  null,
                  allowed ? "SUCCESS" : "DENIED",
                  allowed ? "AUTHENTICATED" : "INVALID_CREDENTIALS");
              return allowed ? u.id : null;
            });
    if (id == null) {
      throttle.failed(bucket);
      throttle.failed(remote);
      throw new AppException(401, "Invalid email or password.");
    }
    throttle.success(bucket);
    return id;
  }

  private User active(Session s, long id) {
    User u = s.find(User.class, id);
    if (u == null || !u.active)
      throw new AppException(401, "Please sign in with an active account.");
    return u;
  }

  private User locked(Session s, long id) {
    User u = s.find(User.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (u == null || !u.active)
      throw new AppException(401, "Please sign in with an active account.");
    return u;
  }

  private User admin(Session s, long id) {
    User u = active(s, id);
    if (!u.role.equals("ADMIN")) throw new AppException(403, "Administrator access is required.");
    return u;
  }

  public Map<String, Object> account(long id) {
    return db.tx(s -> userDto(active(s, id)));
  }

  private Map<String, Object> userDto(User u) {
    return Map.of(
        "id",
        u.id,
        "name",
        u.name,
        "email",
        u.email,
        "role",
        u.role,
        "active",
        u.active,
        "createdAt",
        u.createdAt.toString());
  }

  private void audit(
      Session s, User actor, String action, StoredFile file, String outcome, String reason) {
    advanced.audit().append(s, actor, action, file, outcome, reason, null, null);
  }

  public AdvancedService advanced() {
    return advanced;
  }

  private long used(Session s, long id) {
    return advanced.used(s, id);
  }

  public Map<String, Object> dashboard(long id) {
    return db.tx(
        s -> {
          active(s, id);
          return Map.of(
              "used",
              used(s, id),
              "quota",
              quota,
              "owned",
              s.createQuery(
                      "select count(f) from StoredFile f where f.owner.id=:id and"
                          + " f.status='ACTIVE'",
                      Long.class)
                  .setParameter("id", id)
                  .getSingleResult(),
              "shared",
              s.createQuery(
                      "select count(p) from FilePermission p where p.recipient.id=:id and"
                          + " p.file.status='ACTIVE' and p.file.owner.active=true and p.revokedAt"
                          + " is null and (p.expiresAt is null or p.expiresAt>:now)",
                      Long.class)
                  .setParameter("id", id)
                  .setParameter("now", clock.instant())
                  .getSingleResult());
        });
  }

  public String upload(long id, String name, byte[] bytes, String description) {
    String mime = new UploadValidator().validate(name, bytes),
        clean = text(description, 1000, "Description");
    String fileId = UUID.randomUUID().toString(), storageKey = UUID.randomUUID().toString();
    Crypto.Encrypted encrypted;
    try {
      encrypted = crypto.encrypt(fileId, bytes);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Encryption failed", e);
    }
    try {
      return db.tx(
          s -> {
            User owner = locked(s, id);
            if (used(s, id) + bytes.length > quota)
              throw AppException.invalid("Your storage quota would be exceeded.");
            StoredFile f = new StoredFile();
            f.id = fileId;
            f.owner = owner;
            f.originalName = name;
            f.storageKey = storageKey;
            f.mime = mime;
            f.size = bytes.length;
            f.description = clean;
            f.wrappedKey = encrypted.wrappedKey();
            f.wrappingIv = encrypted.wrappingIv();
            f.fileIv = encrypted.fileIv();
            f.createdAt = clock.instant();
            f.updatedAt = f.createdAt;
            try {
              storage.write(storageKey, encrypted.bytes());
            } catch (IOException e) {
              throw new IllegalStateException("Could not save encrypted file", e);
            }
            s.persist(f);
            advanced.captureInitialVersion(s, f);
            audit(s, owner, "UPLOAD", f, "SUCCESS", "STORED");
            return fileId;
          });
    } catch (RuntimeException e) {
      // An ambiguous commit must not cause a committed file to lose its bytes.
      try {
        boolean exists = db.tx(s -> s.find(StoredFile.class, fileId) != null);
        if (!exists) storage.delete(storageKey);
      } catch (RuntimeException | IOException cleanup) {
        System.err.println("Upload cleanup deferred to orphan sweep.");
      }
      throw e;
    }
  }

  private StoredFile ownerFile(Session s, long id, String fileId, boolean lock) {
    active(s, id);
    validId(fileId);
    StoredFile f =
        lock
            ? s.find(StoredFile.class, fileId, LockModeType.PESSIMISTIC_WRITE)
            : s.find(StoredFile.class, fileId);
    if (f == null || !f.status.equals("ACTIVE") || !f.owner.getId().equals(id))
      throw AppException.unavailable();
    return f;
  }

  private void validId(String id) {
    if (id == null || !id.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
      throw AppException.unavailable();
  }

  public void checkDownload(long id, String fileId) {
    advanced.checkDownload(id, fileId);
  }

  public Download download(long id, String fileId) {
    return advanced.download(id, fileId, null, false);
  }

  private Map<String, Object> fileDto(StoredFile entity) {
    StoredFile f = org.hibernate.Hibernate.unproxy(entity, StoredFile.class);
    return Map.of(
        "id",
        f.id,
        "name",
        f.originalName,
        "size",
        f.size,
        "mime",
        f.mime,
        "description",
        f.description == null ? "" : f.description,
        "createdAt",
        f.createdAt.toString(),
        "owner",
        f.owner.getName());
  }

  public List<Map<String, Object>> files(long id, String search, int page, boolean received) {
    if (received) return advanced.sharedFiles(id, search, page);
    return db.tx(
        s -> {
          active(s, id);
          String q = text(search, 100, "Search").toLowerCase(Locale.ROOT);
          if (received)
            return s
                .createQuery(
                    "from FilePermission p join fetch p.file f join fetch f.owner where"
                        + " p.recipient.id=:id and f.status='ACTIVE' and f.owner.active=true and"
                        + " p.revokedAt is null and (p.expiresAt is null or p.expiresAt>:now) and"
                        + " (:q is null or locate(:q,lower(f.originalName))>0) order by p.grantedAt"
                        + " desc",
                    FilePermission.class)
                .setParameter("id", id)
                .setParameter("now", clock.instant())
                .setParameter("q", q)
                .setFirstResult(offset(page))
                .setMaxResults(20)
                .getResultList()
                .stream()
                .map(
                    p -> {
                      Map<String, Object> dto = new HashMap<>(fileDto(p.file));
                      dto.put(
                          "expiresAt", p.expiresAt == null ? "No expiry" : p.expiresAt.toString());
                      return dto;
                    })
                .toList();
          return s
              .createQuery(
                  "from StoredFile f join fetch f.owner where f.owner.id=:id and f.status='ACTIVE'"
                      + " and (:q is null or locate(:q,lower(f.originalName))>0) order by"
                      + " f.createdAt desc",
                  StoredFile.class)
              .setParameter("id", id)
              .setParameter("q", q)
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .getResultList()
              .stream()
              .map(this::fileDto)
              .toList();
        });
  }

  private int offset(int page) {
    if (page < 0 || page > 100000) throw AppException.invalid("Invalid page.");
    return page * 20;
  }

  public Map<String, Object> details(long id, String fileId) {
    return db.tx(
        s -> {
          StoredFile f = ownerFile(s, id, fileId, false);
          Map<String, Object> dto = new HashMap<>(fileDto(f));
          dto.put("classification", f.classification);
          dto.put("listed", f.listed);
          dto.put("grants", advanced.grants(id, fileId));
          return dto;
        });
  }

  public void describe(long id, String fileId, String description) {
    String clean = text(description, 1000, "Description");
    db.tx(
        s -> {
          StoredFile f = ownerFile(s, id, fileId, true);
          f.description = clean;
          f.updatedAt = clock.instant();
          audit(s, active(s, id), "EDIT_DESCRIPTION", f, "SUCCESS", "UPDATED");
          return null;
        });
  }

  public void share(long id, String fileId, String email, Instant expires) {
    advanced.share(id, fileId, email, AccessPolicy.downloadOnly(expires), null);
  }

  public void revoke(long id, String fileId, long grantId) {
    advanced.revoke(id, fileId, grantId);
  }

  public void delete(long id, String fileId) {
    db.tx(
        s -> {
          locked(s, id);
          StoredFile f = ownerFile(s, id, fileId, true);
          f.status = "DELETED";
          advanced.cancelRequestsForDeletion(s, f, id);
          for (FileVersion content :
              s.createQuery("from FileVersion where fileId=:file", FileVersion.class)
                  .setParameter("file", fileId)
                  .list()) content.status = "DELETED";
          f.updatedAt = clock.instant();
          for (FilePermission p :
              s.createQuery("from FilePermission where file.id=:file", FilePermission.class)
                  .setParameter("file", fileId)
                  .list()) p.revokedAt = clock.instant();
          audit(s, active(s, id), "DELETE", f, "SUCCESS", "TOMBSTONED");
          return null;
        });
    cleanup();
  }

  public void cleanup() {
    db.tx(
        s -> {
          for (StoredFile f :
              s.createQuery("from StoredFile where status='DELETED'", StoredFile.class).list()) {
            try {
              storage.delete(f.storageKey);
            } catch (IOException e) {
              System.err.println("Deleted file cleanup will be retried.");
            }
          }
          for (FileVersion content :
              s.createQuery("from FileVersion where status='DELETED'", FileVersion.class).list()) {
            try {
              storage.delete(content.storageKey);
            } catch (IOException e) {
              System.err.println("Version cleanup will be retried.");
            }
          }
          Set<String> referenced =
              new HashSet<>(
                  s.createQuery("select storageKey from StoredFile", String.class).list());
          referenced.addAll(
              s.createQuery("select storageKey from FileVersion", String.class).list());
          try {
            storage.cleanOrphans(referenced, clock.instant().minusSeconds(3600));
          } catch (IOException e) {
            System.err.println("Orphan cleanup will be retried.");
          }
          return null;
        });
  }

  public List<Map<String, Object>> users(long id, String search, int page) {
    return db.tx(
        s -> {
          admin(s, id);
          return s
              .createQuery(
                  "from User where :q is null or locate(:q,lower(email))>0 or"
                      + " locate(:q,lower(name))>0 order by id",
                  User.class)
              .setParameter("q", text(search, 100, "Search").toLowerCase(Locale.ROOT))
              .setFirstResult(offset(page))
              .setMaxResults(20)
              .list()
              .stream()
              .map(this::userDto)
              .toList();
        });
  }

  public void setActive(long id, long target, boolean enabled) {
    db.tx(
        s -> {
          admin(s, id);
          User user = s.find(User.class, target, LockModeType.PESSIMISTIC_WRITE);
          if (user == null) throw AppException.invalid("User unavailable.");
          if (user.role.equals("ADMIN"))
            throw AppException.invalid(
                "Administrator accounts are protected from disabling in this demo.");
          user.active = enabled;
          audit(
              s,
              active(s, id),
              "ACCOUNT_STATUS",
              null,
              "SUCCESS",
              (enabled ? "ACTIVATED_USER_" : "DISABLED_USER_") + target);
          return null;
        });
  }

  public List<Map<String, Object>> activity(
      long id,
      boolean all,
      String actor,
      String action,
      String outcome,
      LocalDate from,
      LocalDate to,
      int page) {
    return db.tx(
        s -> {
          if (all) admin(s, id);
          else active(s, id);
          String hql = "from AuditLog a left join fetch a.actor left join fetch a.file where 1=1";
          if (!all)
            hql +=
                " and (a.actor.id=:id or a.file.owner.id=:id or exists (select p.id from"
                    + " FilePermission p where p.file=a.file and p.recipient.id=:id))";
          if (actor != null && !actor.isBlank()) hql += " and a.actor.email=:actor";
          if (action != null && !action.isBlank()) hql += " and a.action=:action";
          if (outcome != null && !outcome.isBlank()) hql += " and a.outcome=:outcome";
          if (from != null) hql += " and a.occurredAt>=:from";
          if (to != null) hql += " and a.occurredAt<:to";
          var query = s.createQuery(hql + " order by a.occurredAt desc, a.id desc", AuditLog.class);
          if (!all) query.setParameter("id", id);
          if (actor != null && !actor.isBlank()) query.setParameter("actor", email(actor));
          if (action != null && !action.isBlank())
            query.setParameter("action", text(action, 40, "Action"));
          if (outcome != null && !outcome.isBlank())
            query.setParameter("outcome", text(outcome, 10, "Outcome"));
          if (from != null)
            query.setParameter("from", from.atStartOfDay().toInstant(ZoneOffset.UTC));
          if (to != null)
            query.setParameter("to", to.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC));
          return query.setFirstResult(offset(page)).setMaxResults(20).list().stream()
              .map(
                  a ->
                      Map.<String, Object>of(
                          "actor",
                          a.actor == null ? "Unknown" : a.actor.getEmail(),
                          "action",
                          a.action,
                          "outcome",
                          a.outcome,
                          "reason",
                          a.reason,
                          "file",
                          a.file == null ? "" : a.file.getId(),
                          "occurredAt",
                          a.occurredAt.toString()))
              .toList();
        });
  }
}
