package com.securefiles.security;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public final class Crypto {
  private final SecretKey master;
  private final SecureRandom random = new SecureRandom();

  public record Encrypted(byte[] bytes, byte[] wrappedKey, byte[] wrappingIv, byte[] fileIv) {}

  public Crypto(String base64) {
    try {
      byte[] bytes = Base64.getDecoder().decode(base64 == null ? "" : base64);
      if (bytes.length != 32) throw new IllegalArgumentException();
      master = new SecretKeySpec(bytes, "AES");
      Arrays.fill(bytes, (byte) 0);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(
          "SF_MASTER_KEY must be Base64 encoding of exactly 32 random bytes.");
    }
  }

  private byte[] iv() {
    byte[] bytes = new byte[12];
    random.nextBytes(bytes);
    return bytes;
  }

  private byte[] crypt(int mode, SecretKey key, byte[] iv, String aad, byte[] bytes)
      throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(mode, key, new GCMParameterSpec(128, iv));
    cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
    return cipher.doFinal(bytes);
  }

  public Encrypted encrypt(String id, byte[] plain) throws GeneralSecurityException {
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(256);
    byte[] key = generator.generateKey().getEncoded();
    byte[] fileIv = iv(), wrappingIv = iv();
    try {
      byte[] bytes =
          crypt(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), fileIv, "file:v1:" + id, plain);
      byte[] wrapped = crypt(Cipher.ENCRYPT_MODE, master, wrappingIv, "key:v1:" + id, key);
      return new Encrypted(bytes, wrapped, wrappingIv, fileIv);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  public byte[] decrypt(String id, Encrypted value) throws GeneralSecurityException {
    byte[] key =
        crypt(Cipher.DECRYPT_MODE, master, value.wrappingIv(), "key:v1:" + id, value.wrappedKey());
    try {
      return crypt(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          value.fileIv(),
          "file:v1:" + id,
          value.bytes());
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }
}
