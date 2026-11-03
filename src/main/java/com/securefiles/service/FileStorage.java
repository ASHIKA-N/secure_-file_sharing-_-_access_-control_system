package com.securefiles.service;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

public class FileStorage {
  private final Path root;

  public FileStorage(Path root) throws IOException {
    this.root = root.toAbsolutePath().normalize();
    Files.createDirectories(this.root);
    restrict(this.root);
  }

  public static void restrict(Path path) throws IOException {
    if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null)
      Files.setPosixFilePermissions(
          path,
          PosixFilePermissions.fromString(Files.isDirectory(path) ? "rwx------" : "rw-------"));
    else {
      AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
      if (acl == null)
        throw new IOException("Storage must support POSIX permissions or Windows ACLs.");
      acl.setAcl(
          List.of(
              AclEntry.newBuilder()
                  .setType(AclEntryType.ALLOW)
                  .setPrincipal(acl.getOwner())
                  .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                  .build()));
    }
  }

  public Path root() {
    return root;
  }

  private Path path(String key) {
    if (key == null || !key.matches("[0-9a-f-]{36}"))
      throw new IllegalArgumentException("Invalid internal storage key");
    return root.resolve(key + ".bin");
  }

  public void write(String key, byte[] encrypted) throws IOException {
    Path temporary = Files.createTempFile(root, "upload-", ".tmp");
    try {
      restrict(temporary);
      Files.write(temporary, encrypted);
      try {
        Files.move(temporary, path(key), StandardCopyOption.ATOMIC_MOVE);
      } catch (AtomicMoveNotSupportedException e) {
        Files.move(temporary, path(key));
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  public byte[] read(String key) throws IOException {
    Path path = path(key);
    if (Files.size(path) > 10L * 1024 * 1024 + 16) throw new IOException("Invalid stored size");
    return Files.readAllBytes(path);
  }

  public void delete(String key) throws IOException {
    Files.deleteIfExists(path(key));
  }

  public void cleanOrphans(Set<String> referenced, java.time.Instant before) throws IOException {
    try (var paths = Files.list(root)) {
      for (Path p : paths.toList()) {
        String name = p.getFileName().toString();
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)
            || Files.getLastModifiedTime(p).toInstant().isAfter(before)) continue;
        if (name.startsWith("upload-") && name.endsWith(".tmp")
            || name.endsWith(".bin") && !referenced.contains(name.substring(0, name.length() - 4)))
          Files.deleteIfExists(p);
      }
    }
  }
}
