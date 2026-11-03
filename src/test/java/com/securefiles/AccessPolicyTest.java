package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import com.securefiles.exception.AppException;
import com.securefiles.security.AccessPolicy;
import java.time.*;
import org.junit.jupiter.api.Test;

class AccessPolicyTest {
  @Test
  void dailyAndOvernightBoundaries() {
    assertTrue(AccessPolicy.inWindow(Instant.parse("2026-11-02T09:00:00Z"), 540, 600, "UTC"));
    assertFalse(AccessPolicy.inWindow(Instant.parse("2026-11-02T10:00:00Z"), 540, 600, "UTC"));
    assertTrue(AccessPolicy.inWindow(Instant.parse("2026-11-02T23:00:00Z"), 1320, 120, "UTC"));
    assertTrue(AccessPolicy.inWindow(Instant.parse("2026-11-03T01:59:59Z"), 1320, 120, "UTC"));
    assertFalse(AccessPolicy.inWindow(Instant.parse("2026-11-03T02:00:00Z"), 1320, 120, "UTC"));
  }

  @Test
  void daylightSavingUsesNamedZoneWallClock() {
    // Both occurrences of 01:30 are inside the window when New York falls back.
    assertTrue(
        AccessPolicy.inWindow(Instant.parse("2026-11-01T05:30:00Z"), 60, 120, "America/New_York"));
    assertTrue(
        AccessPolicy.inWindow(Instant.parse("2026-11-01T06:30:00Z"), 60, 120, "America/New_York"));
    // The skipped 02:00 hour has no eligible instant during the spring transition.
    assertFalse(
        AccessPolicy.inWindow(Instant.parse("2026-03-08T07:00:00Z"), 120, 180, "America/New_York"));
    assertThrows(
        AppException.class,
        () -> new AccessPolicy(true, 0, false, null, false, null, null, null, null, false, null));
  }
}
