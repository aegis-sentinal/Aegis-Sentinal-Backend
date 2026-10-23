package com.aegis.identity.infrastructure.email;

import com.aegis.identity.application.port.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DevEmailServiceAdapter implements EmailService {

  private static final Logger log = LoggerFactory.getLogger(DevEmailServiceAdapter.class);

  private final String baseUrl;

  public DevEmailServiceAdapter(
      @Value("${aegis.email.base-url:http://localhost:3000}") String baseUrl) {
    this.baseUrl = baseUrl;
  }

  @Override
  public void sendVerificationEmail(String recipientEmail, String rawToken) {
    String verificationUrl = baseUrl + "/auth/verify-email?token=" + rawToken;
    log.info(
        "[DEV EMAIL SERVICE] Verification email sent to {}. Verification URL: {}",
        recipientEmail,
        verificationUrl);
  }
}
