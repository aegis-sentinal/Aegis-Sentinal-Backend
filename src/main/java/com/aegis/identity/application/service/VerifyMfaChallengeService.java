package com.aegis.identity.application.service;

import com.aegis.identity.application.port.TotpService;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.domain.entity.MfaChallenge;
import com.aegis.identity.domain.entity.MfaCredential;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaChallengeRepository;
import com.aegis.identity.domain.repository.MfaCredentialRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import com.aegis.identity.infrastructure.security.mfa.SecretEncryptionService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VerifyMfaChallengeService {

  private final MfaChallengeRepository challengeRepository;
  private final MfaCredentialRepository credentialRepository;
  private final TotpService totpService;
  private final SecretEncryptionService encryptionService;
  private final CreateSessionService createSessionService;
  private final SecurityAuditLogger auditLogger;

  public VerifyMfaChallengeService(
      MfaChallengeRepository challengeRepository,
      MfaCredentialRepository credentialRepository,
      TotpService totpService,
      SecretEncryptionService encryptionService,
      CreateSessionService createSessionService,
      SecurityAuditLogger auditLogger) {
    this.challengeRepository = challengeRepository;
    this.credentialRepository = credentialRepository;
    this.totpService = totpService;
    this.encryptionService = encryptionService;
    this.createSessionService = createSessionService;
    this.auditLogger = auditLogger;
  }

  @Transactional
  public AuthenticationResult execute(UUID challengeId, String code) {
    MfaChallenge challenge =
        challengeRepository
            .findById(challengeId)
            .orElseThrow(() -> new IllegalArgumentException("Invalid or expired MFA challenge"));

    if (challenge.isCompleted()) {
      throw new IllegalArgumentException("MFA challenge has already been completed");
    }

    User user = challenge.getUser();

    if (challenge.isExpired()) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.MFA_CHALLENGE_EXPIRED,
              user.getId(),
              "FAILURE",
              "MFA challenge expired"));
      throw new IllegalArgumentException("MFA challenge has expired");
    }

    if (challenge.getAttempts() >= 5) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.MFA_VERIFICATION_FAILED,
              user.getId(),
              "FAILURE",
              "Maximum MFA attempts exceeded for challenge"));
      throw new IllegalArgumentException("Maximum MFA verification attempts exceeded");
    }

    challenge.setAttempts(challenge.getAttempts() + 1);
    challengeRepository.save(challenge);

    MfaCredential credential =
        credentialRepository
            .findByUserId(user.getId())
            .orElseThrow(() -> new IllegalStateException("MFA credential not found for user"));

    String secret = encryptionService.decrypt(credential.getEncryptedSecret());

    if (!totpService.verify(secret, code)) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.MFA_VERIFICATION_FAILED,
              user.getId(),
              "FAILURE",
              "Invalid TOTP code supplied during login challenge"));
      throw new IllegalArgumentException("Invalid TOTP code");
    }

    challenge.setCompletedAt(Instant.now());
    challengeRepository.save(challenge);

    AuthenticationResult result =
        createSessionService.issueTokensAndCreateSession(user, List.of("pwd", "totp"));

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.MFA_VERIFICATION_SUCCESS,
            user.getId(),
            "SUCCESS",
            "MFA TOTP challenge verified successfully"));

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.AUTH_LOGIN_SUCCESS,
            user.getId(),
            "SUCCESS",
            "Login completed via password + TOTP MFA"));

    return result;
  }
}
