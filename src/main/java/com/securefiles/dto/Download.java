package com.securefiles.dto;

/** Created only after complete ciphertext authentication. */
public record Download(String id, String name, byte[] bytes) {}
