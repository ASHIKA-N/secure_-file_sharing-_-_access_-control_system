package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "otp_challenge")
public class OtpChallenge {
  @Id
  @Column(length = 36)
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

  @Column(nullable = false, length = 64)
  public String verifier;

  @Column(nullable = false)
  public int attempts;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  @Column(name = "consumed_at")
  public Instant consumedAt;

  @Column(nullable = false)
  public boolean delivered;

  @Version public long version;
}
