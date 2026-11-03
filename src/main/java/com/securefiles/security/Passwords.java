package com.securefiles.security;

import com.securefiles.exception.AppException;
import de.mkammerer.argon2.*;
import java.util.Arrays;

public final class Passwords {
  private Passwords() {}

  public static String hash(String password) {
    if (password == null || password.length() < 12 || password.length() > 128)
      throw AppException.invalid("Use a password between 12 and 128 characters.");
    char[] chars = password.toCharArray();
    try {
      return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id).hash(2, 19456, 1, chars);
    } finally {
      Arrays.fill(chars, '\0');
    }
  }

  public static boolean verify(String hash, String password) {
    if (password == null || password.length() > 128) return false;
    char[] chars = password.toCharArray();
    try {
      return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id).verify(hash, chars);
    } finally {
      Arrays.fill(chars, '\0');
    }
  }
}
