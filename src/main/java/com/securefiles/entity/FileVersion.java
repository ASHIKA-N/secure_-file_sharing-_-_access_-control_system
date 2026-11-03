package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "file_version")
public class FileVersion {
  @Column(name = "crypto_version", nullable = false)
  public int cryptoVersion = 1;

  @Id
  @Column(length = 36)
  public String id;

  @Column(name = "file_id", nullable = false, length = 36)
  public String fileId;

  @Column(name = "version_number", nullable = false)
  public int number;

  @Column(name = "crypto_id", nullable = false, length = 36)
  public String cryptoId;

  @Column(name = "storage_key", nullable = false, unique = true, length = 36)
  public String storageKey;

  @Column(name = "original_name", nullable = false, length = 160)
  public String originalName;

  @Column(nullable = false, length = 100)
  public String mime;

  @Column(name = "size_bytes", nullable = false)
  public long size;

  @Column(name = "wrapped_key", nullable = false, length = 48)
  public byte[] wrappedKey;

  @Column(name = "wrapping_iv", nullable = false, length = 12)
  public byte[] wrappingIv;

  @Column(name = "file_iv", nullable = false, length = 12)
  public byte[] fileIv;

  @Column(nullable = false, length = 15)
  public String status = "ACTIVE";

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Version public long version;
}
