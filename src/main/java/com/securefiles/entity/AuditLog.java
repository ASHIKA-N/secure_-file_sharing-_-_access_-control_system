package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_log")
public class AuditLog {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "actor_id")
  public User actor;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id")
  public StoredFile file;

  @Column(nullable = false, length = 40)
  public String action;

  @Column(nullable = false, length = 10)
  public String outcome;

  @Column(name = "reason_code", nullable = false, length = 60)
  public String reason;

  @Column(name = "occurred_at", nullable = false)
  public Instant occurredAt;

  @Column(name = "chain_sequence", unique = true)
  public Long sequence;

  @Column(name = "previous_hash", length = 64)
  public String previousHash;

  @Column(name = "event_hash", length = 64)
  public String eventHash;

  @Column(name = "served_version", length = 36)
  public String servedVersion;

  @Column(name = "attempt_hash", length = 64)
  public String attemptHash;
}
