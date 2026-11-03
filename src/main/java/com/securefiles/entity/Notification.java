package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "notification")
public class Notification {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @Column(name = "user_id", nullable = false)
  public long userId;

  @Column(name = "file_id", length = 36)
  public String fileId;

  @Column(nullable = false, length = 500)
  public String message;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "read_at")
  public Instant readAt;
}
