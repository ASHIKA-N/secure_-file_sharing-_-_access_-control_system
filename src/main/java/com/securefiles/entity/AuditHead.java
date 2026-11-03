package com.securefiles.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "audit_head")
public class AuditHead {
  @Id public int id = 1;

  @Column(name = "last_sequence", nullable = false)
  public long sequence;

  @Column(name = "last_hash", nullable = false, length = 64)
  public String hash = "0".repeat(64);

  @Version public long version;
}
