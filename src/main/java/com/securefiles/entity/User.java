package com.securefiles.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "app_user")
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @Column(nullable = false, length = 100)
  public String name;

  @Column(name = "normalized_email", nullable = false, unique = true, length = 254)
  public String email;

  @Column(name = "password_hash", nullable = false, length = 255)
  public String passwordHash;

  @Column(nullable = false, length = 10)
  public String role = "USER";

  @Column(nullable = false)
  public boolean active = true;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Version public long version;

  public Long getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getEmail() {
    return email;
  }

  public boolean isActive() {
    return active;
  }
}
