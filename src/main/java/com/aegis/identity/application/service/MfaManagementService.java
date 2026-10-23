package com.aegis.identity.application.service;

import com.aegis.common.util.HashUtil;
import com.aegis.identity.api.dto.MfaSetupVerificationResponse;
import com.aegis.identity.api.dto.MfaStatusResponse;
import com.aegis.identity.application.port.PasswordHasher;
import com.aegis.identity.application.port.TotpService;
import com.aegis.identity.domain.entity.MfaCredential;
import com.aegis.identity.domain.entity.MfaRecoveryCode;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaChallengeRepository;
import com.aegis.identity.domain.repository.MfaCredentialRepository;
import com.aegis.identity.domain.repository.MfaRecoveryCodeRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import com.aegis.identity.infrastructure.security.mfa.SecretEncryptionService;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaManagementService {

  private final UserRepository userRepository;
  private final MfaCredentialRepository credentialRepository;
  private final MfaRecoveryCodeRepository recoveryCodeRepository;
  private final MfaChallengeRepository challengeRepository;
  private final PasswordHasher passwordHasher;
  private final TotpService totpService;
  private final SecretEncryptionService encryptionService;
  private final MfaVerificationService verificationService;
  private final SecurityAuditLogger auditLogger;

  public MfaManagementService(
      UserRepository userRepository,
      MfaCredentialRepository credentialRepository,
      MfaRecoveryCodeRepository recoveryCodeRepository,
      MfaChallengeRepository challengeRepository,
      PasswordHasher passwordHasher,
      TotpService totpService,
      SecretEncryptionService encryptionService,
      MfaVerificationService verificationService,
      SecurityAuditLogger auditLogger) {
    this.userRepository = userRepository;
    this.credentialRepository = credentialRepository;
    this.recoveryCodeRepository = recoveryCodeRepository;
    this.challengeRepository = challengeRepository;
    this.passwordHasher = passwordHasher;
    this.totpService = totpService;
    this.encryptionService = encryptionService;
    this.verificationService = verificationService;
    this.auditLogger = auditLogger;
  }

  @Transactional(readOnly = true)
  public MfaStatusResponse getMfaStatus(User user) {
    return new MfaStatusResponse(Boolean.TRUE.equals(user.getIsMfaEnabled()));
  }

  @Transactional
  public void disableMfa(User user, String password, String code) {
    if (!passwordHasher.matches(password, user.getPasswordHash())) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.MFA_VERIFICATION_FAILED,
              user.getId(),
              "FAILURE",
              "Incorrect password supplied during MFA disable attempt"));
      throw new IllegalArgumentException("Invalid password");
    }

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
              "Invalid TOTP code supplied during MFA disable attempt"));
      throw new IllegalArgumentException("Invalid TOTP code");
    }

    user.setIsMfaEnabled(false);
    userRepository.save(user);

    credentialRepository.deleteByUserId(user.getId());
    recoveryCodeRepository.deleteByUserId(user.getId());
    challengeRepository.deleteByUserId(user.getId());

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.MFA_DISABLED, user.getId(), "SUCCESS", "MFA disabled successfully"));
  }

  @Transactional
  public MfaSetupVerificationResponse regenerateRecoveryCodes(User user, String code) {
    if (!Boolean.TRUE.equals(user.getIsMfaEnabled())) {
      throw new IllegalStateException("MFA is not enabled for this account");
    }

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
              "Invalid TOTP code supplied during recovery code regeneration"));
      throw new IllegalArgumentException("Invalid TOTP code");
    }

    recoveryCodeRepository.deleteByUserId(user.getId());

    List<String> rawRecoveryCodes = verificationService.generateRecoveryCodes(10);
    List<MfaRecoveryCode> recoveryEntities = new ArrayList<>();
    for (String rawCode : rawRecoveryCodes) {
      String codeHash = HashUtil.sha256Hex(rawCode.replace("-", "").toUpperCase());
      recoveryEntities.add(MfaRecoveryCode.builder().user(user).codeHash(codeHash).build());
    }
    recoveryCodeRepository.saveAll(recoveryEntities);

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.MFA_RECOVERY_CODES_REGENERATED,
            user.getId(),
            "SUCCESS",
            "MFA recovery codes regenerated"));

    return new MfaSetupVerificationResponse(
        "Recovery codes regenerated successfully", rawRecoveryCodes);
  }
}
