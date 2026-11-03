package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "access_request")
public class AccessRequest {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @Column(name = "file_id", nullable = false, length = 36)
  public String fileId;

  @Column(name = "requester_id", nullable = false)
  public long requesterId;

  @Column(nullable = false, length = 500)
  public String reason;

  @Column(nullable = false, length = 15)
  public String status = "PENDING";

  @Column(name = "pending_key", unique = true, length = 80)
  public String pendingKey;

  @Column(name = "decision_note", length = 500)
  public String decisionNote;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "decided_at")
  public Instant decidedAt;

  @Version public long version;
}
