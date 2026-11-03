package com.securefiles.service;

import com.securefiles.entity.*;
import com.securefiles.exception.AppException;
import com.securefiles.security.AccessPolicy;
import jakarta.persistence.LockModeType;
import java.time.*;
import java.util.*;
import org.hibernate.Session;

/** All file operations resolve the same active version and ancestor conditions here. */
public final class PermissionEngine {
  public record Access(
      User actor,
      StoredFile file,
      FileVersion content,
      FilePermission grant,
      List<FilePermission> chain,
      boolean otp) {}

  private final Clock clock;

  public PermissionEngine(Clock clock) {
    this.clock = clock;
  }

  public User active(Session s, long id) {
    User u = s.find(User.class, id);
    if (u != null) u = org.hibernate.Hibernate.unproxy(u, User.class);
    if (u == null || !u.isActive())
      throw new AppException(401, "Please sign in with an active account.");
    return u;
  }

  public User admin(Session s, long id) {
    User u = active(s, id);
    if (!u.role.equals("ADMIN")) throw new AppException(403, "Administrator access is required.");
    return u;
  }

  public StoredFile file(Session s, String id, boolean lock) {
    if (id == null || !id.matches("[0-9a-f-]{36}")) throw AppException.unavailable();
    StoredFile f =
        lock
            ? s.find(StoredFile.class, id, LockModeType.PESSIMISTIC_WRITE)
            : s.find(StoredFile.class, id);
    if (f != null) f = org.hibernate.Hibernate.unproxy(f, StoredFile.class);
    if (f == null || !f.status.equals("ACTIVE") || !f.owner.isActive())
      throw AppException.unavailable();
    return f;
  }

  public StoredFile owner(Session s, long actor, String file, boolean lock) {
    active(s, actor);
    StoredFile f = file(s, file, lock);
    if (!f.owner.getId().equals(actor)) throw AppException.unavailable();
    return f;
  }

  public Access resolve(
      Session s,
      long actorId,
      String fileId,
      String action,
      String requestedVersion,
      boolean allowance,
      boolean lock) {
    User actor = active(s, actorId);
    StoredFile file = file(s, fileId, lock);
    FilePermission leaf = null;
    List<FilePermission> chain = new ArrayList<>();
    if (!file.owner.getId().equals(actorId)) {
      leaf =
          s.createQuery(
                  "from FilePermission where file.id=:file and recipient.id=:actor",
                  FilePermission.class)
              .setParameter("file", fileId)
              .setParameter("actor", actorId)
              .uniqueResult();
      if (leaf == null) throw AppException.unavailable();
      Set<Long> seen = new HashSet<>();
      FilePermission p = leaf;
      while (p != null) {
        if (!seen.add(p.id) || chain.size() >= 3 || !p.file.getId().equals(fileId))
          throw AppException.unavailable();
        chain.add(p);
        p = p.parentId == null ? null : s.find(FilePermission.class, p.parentId);
        if (chain.get(chain.size() - 1).parentId != null && p == null)
          throw AppException.unavailable();
      }
      if (lock) {
        for (Long id : chain.stream().map(p2 -> p2.id).sorted().toList())
          s.lock(s.find(FilePermission.class, id), LockModeType.PESSIMISTIC_WRITE);
      }
      for (int i = 0; i < chain.size(); i++) {
        p = chain.get(i);
        if (p.revokedAt != null
            || !p.recipient.isActive()
            || !p.grantedBy.isActive()
            || p.expiresAt != null && !clock.instant().isBefore(p.expiresAt))
          throw AppException.unavailable();
        // Listing an existing share is metadata access; content still enforces every window.
        if (!action.equals("LIST")
            && !AccessPolicy.inWindow(clock.instant(), p.windowStart, p.windowEnd, p.windowZone))
          throw new AppException(
              403,
              String.format(
                  "Access is outside the allowed hours: %02d:%02d–%02d:%02d %s. Check the named"
                      + " timezone with the file owner.",
                  p.windowStart / 60,
                  p.windowStart % 60,
                  p.windowEnd / 60,
                  p.windowEnd % 60,
                  p.windowZone));
        if (i + 1 < chain.size()) {
          FilePermission parent = chain.get(i + 1);
          if (!parent.reshareAllowed || !p.grantedBy.getId().equals(parent.recipient.getId()))
            throw AppException.unavailable();
        } else if (!p.grantedBy.getId().equals(file.owner.getId()))
          throw AppException.unavailable();
        if (action.equals("DOWNLOAD")) {
          if (!p.downloadAllowed)
            throw new AppException(403, "The file owner has disabled downloads.");
          if (allowance && p.downloadLimit != null && p.downloadsUsed >= p.downloadLimit)
            throw new AppException(
                403, "You have reached the download limit set by the file owner.");
        }
        if (action.equals("VIEW")) {
          if (!p.viewAllowed) throw new AppException(403, "The file owner has disabled viewing.");
          if (allowance && p.viewLimit != null && p.viewsUsed >= p.viewLimit)
            throw new AppException(403, "You have used all permitted views for this file.");
        }
        if (action.equals("RESHARE") && !p.reshareAllowed)
          throw new AppException(
              403, "This file cannot be shared. The file owner has denied resharing permission.");
      }
    }
    String version = requestedVersion;
    if (version == null)
      version =
          leaf != null && leaf.targetVersion != null ? leaf.targetVersion : file.currentVersion;
    FileVersion content = version == null ? null : s.find(FileVersion.class, version);
    if (content == null || !content.fileId.equals(fileId) || !content.status.equals("ACTIVE"))
      throw AppException.unavailable();
    for (FilePermission p : chain)
      if (p.targetVersion != null && !p.targetVersion.equals(content.id))
        throw AppException.unavailable();
    boolean otp =
        file.classification.equals("CONFIDENTIAL") || chain.stream().anyMatch(p -> p.otpRequired);
    return new Access(actor, file, content, leaf, List.copyOf(chain), otp);
  }

  public void consume(Access a, String action) {
    for (FilePermission p : a.chain) {
      if (action.equals("VIEW")) {
        if (p.viewsUsed == Integer.MAX_VALUE)
          throw AppException.invalid("The viewing counter is exhausted.");
        p.viewsUsed++;
      } else if (action.equals("DOWNLOAD")) {
        if (p.downloadsUsed == Integer.MAX_VALUE)
          throw AppException.invalid("The download counter is exhausted.");
        p.downloadsUsed++;
      }
    }
  }

  public String remaining(Access a, boolean views) {
    Integer remaining = null;
    for (FilePermission p : a.chain) {
      Integer limit = views ? p.viewLimit : p.downloadLimit;
      if (limit != null) {
        int n = Math.max(0, limit - (views ? p.viewsUsed : p.downloadsUsed));
        remaining = remaining == null ? n : Math.min(remaining, n);
      }
    }
    return remaining == null ? "Unlimited" : remaining.toString();
  }
}
