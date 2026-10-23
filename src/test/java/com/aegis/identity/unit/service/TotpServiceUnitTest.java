package com.aegis.identity.unit.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.aegis.identity.infrastructure.security.mfa.TotpServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TotpServiceUnitTest {

  private TotpServiceImpl totpService;

  @BeforeEach
  void setUp() {
    totpService = new TotpServiceImpl(6, 30, "SHA1", 1);
  }

  @Test
  @DisplayName("TOTP Service: Generates valid Base32 secret")
  void testGenerateSecret() {
    String secret = totpService.generateSecret();
    assertThat(secret).isNotNull().hasSize(32);
  }

  @Test
  @DisplayName("TOTP Service: Generates valid OTP Auth URI for QR codes")
  void testGenerateOtpAuthUri() {
    String secret = "JBSWY3DPEHPK3PXP";
    String uri = totpService.generateOtpAuthUri("Aegis Sentinel", "admin@example.com", secret);
    assertThat(uri).contains("otpauth://totp/");
    assertThat(uri).contains("secret=" + secret);
    assertThat(uri).contains("issuer=Aegis+Sentinel");
  }

  @Test
  @DisplayName("TOTP Service: Verification rejects invalid code format")
  void testVerify_invalidFormat() {
    String secret = totpService.generateSecret();
    assertThat(totpService.verify(secret, "12345")).isFalse();
    assertThat(totpService.verify(secret, "abc123")).isFalse();
    assertThat(totpService.verify(secret, null)).isFalse();
  }
}
