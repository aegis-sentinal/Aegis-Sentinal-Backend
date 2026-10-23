package com.aegis.identity.infrastructure.security.mfa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SecretEncryptionService {

  private static final String ALGORITHM = "AES/GCM/NoPadding";
  private static final int GCM_TAG_LENGTH_BITS = 128;
  private static final int IV_LENGTH_BYTES = 12;

  private final SecretKey key;
  private final SecureRandom secureRandom = new SecureRandom();

  public SecretEncryptionService(
      @Value("${aegis.security.mfa.encryption-key:AegisMfaSecretEncryptionKey32Byte!}")
          String secretKeyStr) {
    byte[] keyBytes = secretKeyStr.getBytes(StandardCharsets.UTF_8);
    byte[] valid32ByteKey = new byte[32];
    System.arraycopy(keyBytes, 0, valid32ByteKey, 0, Math.min(keyBytes.length, 32));
    this.key = new SecretKeySpec(valid32ByteKey, "AES");
  }

  public String encrypt(String plainSecret) {
    try {
      byte[] iv = new byte[IV_LENGTH_BYTES];
      secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(ALGORITHM);
      GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
      cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

      byte[] cipherText = cipher.doFinal(plainSecret.getBytes(StandardCharsets.UTF_8));

      ByteBuffer byteBuffer = ByteBuffer.allocate(IV_LENGTH_BYTES + cipherText.length);
      byteBuffer.put(iv);
      byteBuffer.put(cipherText);

      return Base64.getEncoder().encodeToString(byteBuffer.array());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to encrypt MFA secret", e);
    }
  }

  public String decrypt(String encryptedSecret) {
    try {
      byte[] decoded = Base64.getDecoder().decode(encryptedSecret);

      ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
      byte[] iv = new byte[IV_LENGTH_BYTES];
      byteBuffer.get(iv);

      byte[] cipherText = new byte[byteBuffer.remaining()];
      byteBuffer.get(cipherText);

      Cipher cipher = Cipher.getInstance(ALGORITHM);
      GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
      cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

      byte[] plainText = cipher.doFinal(cipherText);
      return new String(plainText, StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to decrypt MFA secret", e);
    }
  }
}
