package com.aegis.identity.application.service;

import com.aegis.common.util.HashUtil;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.domain.entity.MfaChallenge;
import com.aegis.identity.domain.entity.MfaRecoveryCode;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaChallengeRepository;
import com.aegis.identity.domain.repository.MfaRecoveryCodeRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VerifyMfaRecoveryService {

  private final MfaChallengeRepository challengeRepository;
  private final MfaRecoveryCodeRepository recoveryCodeRepository;
  private final CreateSessionService createSessionService;
  private final SecurityAuditLogger auditLogger;

  public VerifyMfaRecoveryService(
      MfaChallengeRepository challengeRepository,
      MfaRecoveryCodeRepository recoveryCodeRepository,
      CreateSessionService createSessionService,
      SecurityAuditLogger auditLogger) {
    this.challengeRepository = challengeRepository;
    this.recoveryCodeRepository = recoveryCodeRepository;
    this.createSessionService = createSessionService;
    this.auditLogger = auditLogger;
  }

  @Transactional
  public AuthenticationResult execute(UUID challengeId, String rawRecoveryCode) {
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
              "MFA challenge expired during recovery attempt"));
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

    String normalizedCode = rawRecoveryCode.replaceAll("[^a-zA-Z0-9]", "").toUpperCase();
    String codeHash = HashUtil.sha256Hex(normalizedCode);

    List<MfaRecoveryCode> unusedCodes = recoveryCodeRepository.findUnusedByUserId(user.getId());
    Optional<MfaRecoveryCode> matchingCodeOpt =
        unusedCodes.stream().filter(rc -> rc.getCodeHash().equals(codeHash)).findFirst();

    if (matchingCodeOpt.isEmpty()) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.MFA_VERIFICATION_FAILED,
              user.getId(),
              "FAILURE",
              "Invalid MFA recovery code submitted"));
      throw new IllegalArgumentException("Invalid recovery code");
    }

    MfaRecoveryCode matchingCode = matchingCodeOpt.get();
    matchingCode.setUsedAt(Instant.now());
    recoveryCodeRepository.save(matchingCode);

    challenge.setCompletedAt(Instant.now());
    challengeRepository.save(challenge);

    AuthenticationResult result =
        createSessionService.issueTokensAndCreateSession(user, List.of("pwd", "mfa_recovery"));

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.MFA_RECOVERY_USED,
            user.getId(),
            "SUCCESS",
            "MFA recovery code consumed successfully"));

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.AUTH_LOGIN_SUCCESS,
            user.getId(),
            "SUCCESS",
            "Login completed via MFA recovery code"));

    return result;
  }
}
