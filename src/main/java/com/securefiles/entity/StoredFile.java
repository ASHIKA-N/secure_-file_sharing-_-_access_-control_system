package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "stored_file")
public class StoredFile {
  @Id
  @Column(length = 36)
  public String id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "owner_id")
  public User owner;

  @Column(name = "original_name", nullable = false, length = 160)
  public String originalName;

  @Column(name = "storage_key", nullable = false, unique = true, length = 36)
  public String storageKey;

  @Column(name = "detected_mime_type", nullable = false, length = 100)
  public String mime;

  @Column(name = "size_bytes", nullable = false)
  public long size;

  // Oracle treats an empty description as NULL.
  @Column(length = 1000)
  public String description;

  @Column(name = "wrapped_data_key", nullable = false, length = 48)
  public byte[] wrappedKey;

  @Column(name = "wrapping_iv", nullable = false, length = 12)
  public byte[] wrappingIv;

  @Column(name = "file_iv", nullable = false, length = 12)
  public byte[] fileIv;

  @Column(name = "crypto_version", nullable = false)
  public int cryptoVersion = 1;

  @Column(nullable = false, length = 20)
  public String status = "ACTIVE";

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "updated_at", nullable = false)
  public Instant updatedAt;

  @Version public long version;

  @Column(name = "current_version", length = 36)
  public String currentVersion;

  @Column(nullable = false, length = 15)
  public String classification = "NORMAL";

  @Column(nullable = false)
  public boolean listed;

  public String getId() {
    return id;
  }
}
