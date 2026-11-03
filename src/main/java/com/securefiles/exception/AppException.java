package com.securefiles.exception;

public class AppException extends RuntimeException {
  public final int status;

  public AppException(int status, String message) {
    super(message);
    this.status = status;
  }

  public static AppException unavailable() {
    return new AppException(404, "This file is unavailable.");
  }

  public static AppException invalid(String message) {
    return new AppException(400, message);
  }
}
