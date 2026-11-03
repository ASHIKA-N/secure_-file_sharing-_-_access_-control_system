package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "security_alert")
public class SecurityAlert {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @Column(name = "actor_id", nullable = false)
  public long actorId;

  @Column(name = "owner_id")
  public Long ownerId;

  @Column(name = "file_id", length = 36)
  public String fileId;

  @Column(name = "rule_code", nullable = false, length = 30)
  public String rule;

  @Column(name = "observed_count", nullable = false)
  public long count;

  @Column(name = "window_seconds", nullable = false)
  public int windowSeconds;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(nullable = false, length = 15)
  public String status = "OPEN";

  @Column(name = "reviewed_at")
  public Instant reviewedAt;

  @Column(name = "reviewed_by")
  public Long reviewedBy;

  @Version public long version;
}
