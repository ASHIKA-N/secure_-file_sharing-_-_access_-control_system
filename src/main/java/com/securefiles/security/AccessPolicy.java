package com.securefiles.security;

import com.securefiles.exception.AppException;
import java.time.*;

public record AccessPolicy(
    boolean viewing,
    Integer viewLimit,
    boolean downloading,
    Integer downloadLimit,
    boolean resharing,
    Instant expiresAt,
    Integer startMinute,
    Integer endMinute,
    String timezone,
    boolean otp,
    String targetVersion) {
  public AccessPolicy {
    if (viewLimit != null && (viewLimit < 1 || viewLimit > 1000000)
        || downloadLimit != null && (downloadLimit < 1 || downloadLimit > 1000000))
      throw AppException.invalid("Limits must be positive counts, or blank for unlimited.");
    if ((startMinute == null) != (endMinute == null))
      throw AppException.invalid("Enter both access-hour times.");
    if (startMinute != null) {
      if (startMinute < 0
          || startMinute >= 1440
          || endMinute < 0
          || endMinute >= 1440
          || startMinute.equals(endMinute))
        throw AppException.invalid("Access hours need different valid start and end times.");
      try {
        if (!ZoneId.getAvailableZoneIds().contains(timezone)) throw new IllegalArgumentException();
        ZoneId.of(timezone);
      } catch (Exception e) {
        throw AppException.invalid("Use an IANA timezone, for example Asia/Kolkata.");
      }
    } else timezone = null;
  }

  public static AccessPolicy downloadOnly(Instant expiry) {
    return new AccessPolicy(false, null, true, null, false, expiry, null, null, null, false, null);
  }

  public static boolean inWindow(Instant now, Integer start, Integer end, String timezone) {
    if (start == null) return true;
    ZonedDateTime local = now.atZone(ZoneId.of(timezone));
    int minute = local.getHour() * 60 + local.getMinute();
    // Both occurrences of a repeated wall-clock minute are allowed; skipped minutes never occur.
    return start < end ? minute >= start && minute < end : minute >= start || minute < end;
  }
}
