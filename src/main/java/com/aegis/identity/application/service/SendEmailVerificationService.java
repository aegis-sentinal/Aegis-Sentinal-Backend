package com.aegis.identity.application.service;

import com.aegis.common.util.HashUtil;
import com.aegis.identity.application.port.EmailService;
import com.aegis.identity.domain.entity.EmailVerificationToken;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.EmailVerificationTokenRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SendEmailVerificationService {

  private final EmailVerificationTokenRepository tokenRepository;
  private final EmailService emailService;
  private final SecurityAuditLogger auditLogger;

  public SendEmailVerificationService(
      EmailVerificationTokenRepository tokenRepository,
      EmailService emailService,
      SecurityAuditLogger auditLogger) {
    this.tokenRepository = tokenRepository;
    this.emailService = emailService;
    this.auditLogger = auditLogger;
  }

  @Transactional
  public void execute(User user) {
    tokenRepository.deleteByUserId(user.getId());

    String rawToken = UUID.randomUUID().toString() + UUID.randomUUID().toString();
    String tokenHash = HashUtil.sha256Hex(rawToken);
    Instant expiresAt = Instant.now().plus(24, ChronoUnit.HOURS);

    EmailVerificationToken verificationToken =
        EmailVerificationToken.builder()
            .user(user)
            .tokenHash(tokenHash)
            .expiresAt(expiresAt)
            .build();

    tokenRepository.save(verificationToken);
    emailService.sendVerificationEmail(user.getEmail(), rawToken);

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.EMAIL_VERIFICATION_SENT,
            user.getId(),
            "SUCCESS",
            "Verification email dispatched"));
  }
}
