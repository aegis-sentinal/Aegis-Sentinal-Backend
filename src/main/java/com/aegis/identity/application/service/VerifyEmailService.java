package com.aegis.identity.application.service;

import com.aegis.common.util.HashUtil;
import com.aegis.identity.domain.entity.EmailVerificationToken;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.EmailVerificationTokenRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VerifyEmailService {

  private final EmailVerificationTokenRepository tokenRepository;
  private final UserRepository userRepository;
  private final SecurityAuditLogger auditLogger;

  public VerifyEmailService(
      EmailVerificationTokenRepository tokenRepository,
      UserRepository userRepository,
      SecurityAuditLogger auditLogger) {
    this.tokenRepository = tokenRepository;
    this.userRepository = userRepository;
    this.auditLogger = auditLogger;
  }

  @Transactional
  public void execute(String rawToken) {
    String tokenHash = HashUtil.sha256Hex(rawToken);

    EmailVerificationToken token =
        tokenRepository
            .findByTokenHash(tokenHash)
            .orElseThrow(
                () -> new IllegalArgumentException("Invalid or expired verification token"));

    if (token.isUsed()) {
      throw new IllegalArgumentException("Verification token has already been used");
    }

    if (token.isExpired()) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.EMAIL_VERIFICATION_FAILED,
              token.getUser().getId(),
              "FAILURE",
              "Expired email verification token submitted"));
      throw new IllegalArgumentException("Verification token has expired");
    }

    token.setUsedAt(Instant.now());
    tokenRepository.save(token);

    User user = token.getUser();
    user.setEmailVerified(true);
    userRepository.save(user);

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.EMAIL_VERIFIED, user.getId(), "SUCCESS", "Email verified successfully"));
  }
}
