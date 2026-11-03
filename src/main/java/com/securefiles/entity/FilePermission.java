package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(
    name = "file_permission",
    uniqueConstraints = @UniqueConstraint(columnNames = {"file_id", "recipient_id"}))
public class FilePermission {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "file_id")
  public StoredFile file;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "recipient_id")
  public User recipient;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "granted_by")
  public User grantedBy;

  @Column(nullable = false, length = 10)
  public String permission = "DOWNLOAD";

  @Column(name = "granted_at", nullable = false)
  public Instant grantedAt;

  @Column(name = "expires_at")
  public Instant expiresAt;

  @Column(name = "revoked_at")
  public Instant revokedAt;

  @Version public long version;

  @Column(name = "parent_id")
  public Long parentId;

  @Column(name = "target_version", length = 36)
  public String targetVersion;

  @Column(name = "view_allowed", nullable = false)
  public boolean viewAllowed;

  @Column(name = "download_allowed", nullable = false)
  public boolean downloadAllowed = true;

  @Column(name = "reshare_allowed", nullable = false)
  public boolean reshareAllowed;

  @Column(name = "otp_required", nullable = false)
  public boolean otpRequired;

  @Column(name = "view_limit")
  public Integer viewLimit;

  @Column(name = "download_limit")
  public Integer downloadLimit;

  @Column(name = "views_used", nullable = false)
  public int viewsUsed;

  @Column(name = "downloads_used", nullable = false)
  public int downloadsUsed;

  @Column(name = "window_start")
  public Integer windowStart;

  @Column(name = "window_end")
  public Integer windowEnd;

  @Column(name = "window_zone", length = 100)
  public String windowZone;
}
