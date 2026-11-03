package com.securefiles.service;

import com.securefiles.config.AdvancedConfig;
import com.securefiles.entity.*;
import com.securefiles.repository.Database;
import com.securefiles.security.Authenticators;
import jakarta.persistence.LockModeType;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import org.hibernate.Session;

public final class AuditTrail {
  private final Database db;
  private final Clock clock;
  private final AdvancedConfig config;

  public AuditTrail(Database db, Clock clock, AdvancedConfig config) {
    this.db = db;
    this.clock = clock;
    this.config = config;
    try {
      Files.createDirectories(config.checkpoints());
      FileStorage.restrict(config.checkpoints());
    } catch (IOException e) {
      throw new IllegalStateException("Cannot open private audit checkpoint directory", e);
    }
    db.tx(
        s -> {
          AuditHead head = s.find(AuditHead.class, 1, LockModeType.PESSIMISTIC_WRITE);
          if (head.sequence == 0)
            for (AuditLog event : s.createQuery("from AuditLog order by id", AuditLog.class).list())
              link(s, head, event);
          return null;
        });
  }

  private byte[] canonical(AuditLog e) {
    try {
      var bytes = new ByteArrayOutputStream();
      var out = new DataOutputStream(bytes);
      out.writeInt(1);
      out.writeLong(e.sequence);
      out.writeLong(e.id);
      for (String field :
          new String[] {
            e.actor == null ? null : e.actor.getId().toString(),
            e.action,
            e.file == null ? null : e.file.getId(),
            e.servedVersion,
            e.outcome,
            e.reason,
            e.occurredAt.toString(),
            e.attemptHash
          }) {
        if (field == null) out.writeInt(-1);
        else {
          byte[] utf = field.getBytes(StandardCharsets.UTF_8);
          out.writeInt(utf.length);
          out.write(utf);
        }
      }
      return bytes.toByteArray();
    } catch (IOException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private String digest(String previous, AuditLog e) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(HexFormat.of().parseHex(previous));
      return HexFormat.of().formatHex(md.digest(canonical(e)));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private void link(Session s, AuditHead head, AuditLog event) {
    event.sequence = ++head.sequence;
    event.previousHash = head.hash;
    event.eventHash = digest(head.hash, event);
    head.hash = event.eventHash;
  }

  public void append(
      Session s,
      User actor,
      String action,
      StoredFile file,
      String outcome,
      String reason,
      String version,
      String attemptedId) {
    AuditHead head = s.find(AuditHead.class, 1, LockModeType.PESSIMISTIC_WRITE);
    AuditLog e = new AuditLog();
    e.actor = actor;
    e.action = action;
    e.file = file;
    e.outcome = outcome;
    e.reason = reason;
    e.servedVersion = version;
    e.attemptHash = attemptedId == null ? null : Authenticators.hash(attemptedId);
    // Oracle timestamps retain microseconds; hash the exact value that will be stored.
    e.occurredAt = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MICROS);
    s.persist(e);
    link(s, head, e);
    if (actor != null) {
      s.flush();
      detect(s, e, actor.getId(), null);
      if (file != null) detect(s, e, actor.getId(), file.owner.getId());
    }
  }

  private void detect(Session s, AuditLog event, long actor, Long owner) {
    String scope = owner == null ? "" : " and a.file.owner.id=:owner";
    Object[][] rules = {
      {
        "DENIED_ACCESS",
        300,
        config.deniedThreshold(),
        "a.outcome='DENIED' and a.attemptHash is not null and a.action<>'RESHARE'",
        false
      },
      {
        "DENIED_RESHARE",
        300,
        config.reshareThreshold(),
        "a.outcome='DENIED' and a.action='RESHARE'",
        false
      },
      {
        "DOWNLOAD_STARTS",
        600,
        config.downloadThreshold(),
        "a.action='DOWNLOAD' and a.outcome='SUCCESS'",
        false
      },
      {
        "DISTINCT_IDS",
        300,
        config.distinctThreshold(),
        "a.outcome='DENIED' and a.attemptHash is not null",
        true
      }
    };
    for (Object[] rule : rules) {
      String code = (String) rule[0];
      int seconds = (int) rule[1];
      String select = (boolean) rule[4] ? "count(distinct a.attemptHash)" : "count(a)";
      var count =
          s.createQuery(
                  "select "
                      + select
                      + " from AuditLog a where a.actor.id=:actor and a.occurredAt>=:since and "
                      + rule[3]
                      + scope,
                  Long.class)
              .setParameter("actor", actor)
              .setParameter("since", clock.instant().minusSeconds(seconds));
      if (owner != null) count.setParameter("owner", owner);
      long n = count.getSingleResult();
      if (n < (int) rule[2]) continue;
      var existing =
          s.createQuery(
                  "select count(a) from SecurityAlert a where a.actorId=:actor and a.rule=:rule and"
                      + " a.createdAt>:cooldown and "
                      + (owner == null ? "a.ownerId is null" : "a.ownerId=:owner"),
                  Long.class)
              .setParameter("actor", actor)
              .setParameter("rule", code)
              .setParameter(
                  "cooldown", clock.instant().minusSeconds(config.alertCooldownSeconds()));
      if (owner != null) existing.setParameter("owner", owner);
      if (existing.getSingleResult() > 0) continue;
      SecurityAlert alert = new SecurityAlert();
      alert.actorId = actor;
      alert.ownerId = owner;
      alert.rule = code;
      alert.count = n;
      alert.windowSeconds = seconds;
      alert.createdAt = clock.instant();
      alert.fileId = owner == null ? null : event.file.getId();
      s.persist(alert);
    }
  }

  public Map<String, Object> verify() {
    return db.tx(
        s -> {
          s.find(AuditHead.class, 1, LockModeType.PESSIMISTIC_WRITE);
          String previous = "0".repeat(64);
          long sequence = 0;
          Map<Long, String> hashes = new HashMap<>();
          hashes.put(0L, previous);
          for (AuditLog e :
              s.createQuery("from AuditLog order by sequence", AuditLog.class).list()) {
            if (e.sequence == null
                || e.sequence != sequence + 1
                || !previous.equals(e.previousHash)
                || !digest(previous, e).equals(e.eventHash))
              return result(
                  false, sequence + 1, "Audit inconsistency at sequence " + (sequence + 1));
            sequence = e.sequence;
            previous = e.eventHash;
            hashes.put(sequence, previous);
          }
          AuditHead head = s.find(AuditHead.class, 1);
          if (head.sequence != sequence || !head.hash.equals(previous))
            return result(false, sequence + 1, "Audit tail does not match its head.");
          try (var files = Files.list(config.checkpoints())) {
            for (Path path :
                files.filter(p -> p.getFileName().toString().endsWith(".checkpoint")).toList()) {
              List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
              if (lines.size() != 5) return result(false, 0, "Invalid checkpoint format.");
              String payload = String.join("\n", lines.subList(0, 4));
              if (!Authenticators.equal(
                  Authenticators.hmac(config.checkpointSecret(), payload), lines.get(4)))
                return result(false, 0, "Checkpoint authentication failed.");
              long seq = Long.parseLong(lines.get(1));
              if (!Objects.equals(hashes.get(seq), lines.get(2)))
                return result(
                    false, seq, "Audit truncation or rewrite relative to protected checkpoint.");
            }
          } catch (Exception e) {
            return result(false, 0, "Checkpoint verification failed.");
          }
          return result(
              true, sequence, "Verified " + sequence + " linked events and protected checkpoints.");
        });
  }

  private Map<String, Object> result(boolean valid, long seq, String message) {
    return Map.of("valid", valid, "sequence", seq, "message", message);
  }

  public Map<String, Object> checkpoint() {
    AuditCheckpoint point =
        db.tx(
            s -> {
              AuditHead h = s.find(AuditHead.class, 1, LockModeType.PESSIMISTIC_WRITE);
              AuditCheckpoint p = new AuditCheckpoint();
              p.id = UUID.randomUUID().toString();
              p.sequence = h.sequence;
              p.hash = h.hash;
              p.createdAt = clock.instant();
              return p;
            });
    String payload = "1\n" + point.sequence + "\n" + point.hash + "\n" + point.createdAt;
    Path path = config.checkpoints().resolve(point.id + ".checkpoint");
    try {
      Files.createFile(path);
      FileStorage.restrict(path);
      Files.writeString(
          path,
          payload + "\n" + Authenticators.hmac(config.checkpointSecret(), payload),
          StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("Could not export the protected checkpoint", e);
    }
    db.tx(
        s -> {
          s.persist(point);
          return null;
        });
    return Map.of(
        "sequence", point.sequence, "hash", point.hash, "createdAt", point.createdAt.toString());
  }
}
