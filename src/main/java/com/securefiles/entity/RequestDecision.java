package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "request_decision")
public class RequestDecision {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @Column(name = "request_id", nullable = false)
  public long requestId;

  @Column(name = "actor_id", nullable = false)
  public long actorId;

  @Column(nullable = false, length = 15)
  public String status;

  @Column(length = 500)
  public String note;

  @Column(name = "occurred_at", nullable = false)
  public Instant occurredAt;
}
