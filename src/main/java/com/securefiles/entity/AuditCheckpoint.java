package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_checkpoint")
public class AuditCheckpoint {
  @Id
  @Column(length = 36)
  public String id;

  @Column(name = "chain_sequence", nullable = false)
  public long sequence;

  @Column(name = "chain_hash", nullable = false, length = 64)
  public String hash;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;
}
