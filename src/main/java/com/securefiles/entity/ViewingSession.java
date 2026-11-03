package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "viewing_session")
public class ViewingSession {
  @Column(name = "otp_verified", nullable = false)
  public boolean otpVerified;

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

  @Column(name = "initiation_key", nullable = false, unique = true, length = 120)
  public String initiationKey;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  @Column(name = "closed_at")
  public Instant closedAt;

  @Column(name = "page_count", nullable = false)
  public int pageCount;

  @Version public long version;
}
