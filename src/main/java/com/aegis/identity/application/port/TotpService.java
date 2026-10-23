package com.aegis.identity.application.port;

public interface TotpService {

  String generateSecret();

  boolean verify(String secret, String code);

  boolean verify(String secret, String code, int allowedClockSkew);

  String generateOtpAuthUri(String issuer, String account, String secret);
}
