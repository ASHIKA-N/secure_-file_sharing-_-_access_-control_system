package com.securefiles.security;

import java.time.*;
import java.util.*;

/** A bounded, per-process throttle for a local demonstration. */
public final class LoginThrottle {
  private record Attempt(int count, Instant until) {}

  private final Map<String, Attempt> attempts = new LinkedHashMap<>();
  private final Clock clock;

  public LoginThrottle(Clock clock) {
    this.clock = clock;
  }

  public synchronized boolean allowed(String key) {
    Attempt a = attempts.get(key);
    return a == null || !clock.instant().isBefore(a.until) || a.count < 5;
  }

  public synchronized void failed(String key) {
    Instant now = clock.instant();
    attempts.entrySet().removeIf(e -> !now.isBefore(e.getValue().until));
    if (attempts.size() >= 10000) attempts.remove(attempts.keySet().iterator().next());
    Attempt old = attempts.get(key);
    attempts.put(
        key,
        new Attempt(
            old == null ? 1 : old.count + 1, old == null ? now.plusSeconds(300) : old.until));
  }

  public synchronized void success(String key) {
    attempts.remove(key);
  }
}
