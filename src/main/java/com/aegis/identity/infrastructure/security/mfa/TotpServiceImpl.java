package com.aegis.identity.infrastructure.security.mfa;

import com.aegis.common.util.Base32;
import com.aegis.identity.application.port.TotpService;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TotpServiceImpl implements TotpService {

  private final int digits;
  private final int period;
  private final String algorithm;
  private final int allowedClockSkew;
  private final SecureRandom secureRandom = new SecureRandom();

  public TotpServiceImpl(
      @Value("${aegis.security.mfa.totp.digits:6}") int digits,
      @Value("${aegis.security.mfa.totp.period:30}") int period,
      @Value("${aegis.security.mfa.totp.algorithm:SHA1}") String algorithm,
      @Value("${aegis.security.mfa.totp.allowed-clock-skew:1}") int allowedClockSkew) {
    this.digits = digits;
    this.period = period;
    this.algorithm = algorithm;
    this.allowedClockSkew = allowedClockSkew;
  }

  @Override
  public String generateSecret() {
    byte[] buffer = new byte[20]; // 160 bits secret
    secureRandom.nextBytes(buffer);
    return Base32.encode(buffer);
  }

  @Override
  public boolean verify(String secret, String code) {
    return verify(secret, code, this.allowedClockSkew);
  }

  @Override
  public boolean verify(String secret, String code, int allowedClockSkew) {
    if (secret == null || code == null || code.trim().length() != digits) {
      return false;
    }

    try {
      long currentWindow = System.currentTimeMillis() / 1000 / period;
      for (int i = -allowedClockSkew; i <= allowedClockSkew; i++) {
        String expectedCode = generateOneTimePassword(secret, currentWindow + i);
        if (expectedCode.equals(code.trim())) {
          return true;
        }
      }
    } catch (Exception e) {
      return false;
    }

    return false;
  }

  @Override
  public String generateOtpAuthUri(String issuer, String account, String secret) {
    String label = URLEncoder.encode(issuer + ":" + account, StandardCharsets.UTF_8);
    String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);

    return String.format(
        "otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
        label, secret, encodedIssuer, algorithm, digits, period);
  }

  private String generateOneTimePassword(String secret, long timeWindow)
      throws NoSuchAlgorithmException, InvalidKeyException {

    byte[] keyBytes = Base32.decode(secret);
    byte[] timeBytes = ByteBuffer.allocate(8).putLong(timeWindow).array();

    String macAlgorithm = "Hmac" + algorithm;
    Mac mac = Mac.getInstance(macAlgorithm);
    mac.init(new SecretKeySpec(keyBytes, macAlgorithm));

    byte[] hash = mac.doFinal(timeBytes);

    int offset = hash[hash.length - 1] & 0x0F;
    int binary =
        ((hash[offset] & 0x7F) << 24)
            | ((hash[offset + 1] & 0xFF) << 16)
            | ((hash[offset + 2] & 0xFF) << 8)
            | (hash[offset + 3] & 0xFF);

    int otp = binary % (int) Math.pow(10, digits);
    return String.format("%0" + digits + "d", otp);
  }
}
