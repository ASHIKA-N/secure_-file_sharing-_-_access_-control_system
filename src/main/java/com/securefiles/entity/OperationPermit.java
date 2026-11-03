package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "operation_permit")
public class OperationPermit {
  @Id
  @Column(length = 64)
  public String id;

  @Column(name = "user_id", nullable = false)
  public long userId;

  @Column(name = "file_id", nullable = false, length = 36)
  public String fileId;

  @Column(name = "version_id", nullable = false, length = 36)
  public String versionId;

  @Column(name = "grant_id")
  public Long grantId;

  @Column(nullable = false, length = 10)
  public String operation;

  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  @Column(name = "used_at")
  public Instant usedAt;

  @Version public long version;
}
