package com.aegis.identity.application.service;

import com.aegis.common.util.HashUtil;
import com.aegis.identity.api.dto.MfaSetupVerificationResponse;
import com.aegis.identity.application.port.TotpService;
import com.aegis.identity.domain.entity.MfaCredential;
import com.aegis.identity.domain.entity.MfaRecoveryCode;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaCredentialRepository;
import com.aegis.identity.domain.repository.MfaRecoveryCodeRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import com.aegis.identity.infrastructure.security.mfa.SecretEncryptionService;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaVerificationService {

  private static final String ALPHANUMERIC =
      "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // exclude easily confused chars 0,1,O,I
  private final MfaCredentialRepository mfaCredentialRepository;
  private final MfaRecoveryCodeRepository recoveryCodeRepository;
  private final UserRepository userRepository;
  private final TotpService totpService;
  private final SecretEncryptionService encryptionService;
  private final SecurityAuditLogger auditLogger;
  private final SecureRandom secureRandom = new SecureRandom();

  public MfaVerificationService(
      MfaCredentialRepository mfaCredentialRepository,
      MfaRecoveryCodeRepository recoveryCodeRepository,
      UserRepository userRepository,
      TotpService totpService,
      SecretEncryptionService encryptionService,
      SecurityAuditLogger auditLogger) {
    this.mfaCredentialRepository = mfaCredentialRepository;
    this.recoveryCodeRepository = recoveryCodeRepository;
    this.userRepository = userRepository;
    this.totpService = totpService;
    this.encryptionService = encryptionService;
    this.auditLogger = auditLogger;
  }

  @Transactional
  public MfaSetupVerificationResponse execute(User user, String code) {
    MfaCredential credential =
        mfaCredentialRepository
            .findByUserId(user.getId())
            .orElseThrow(() -> new IllegalStateException("No pending MFA setup found for user"));

    String secret = encryptionService.decrypt(credential.getEncryptedSecret());

    if (!totpService.verify(secret, code)) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.MFA_VERIFICATION_FAILED,
              user.getId(),
              "FAILURE",
              "Invalid TOTP code supplied during MFA setup verification"));
      throw new IllegalArgumentException("Invalid TOTP code");
    }

    credential.setEnabledAt(Instant.now());
    mfaCredentialRepository.save(credential);

    user.setIsMfaEnabled(true);
    userRepository.save(user);

    recoveryCodeRepository.deleteByUserId(user.getId());

    List<String> rawRecoveryCodes = generateRecoveryCodes(10);
    List<MfaRecoveryCode> recoveryEntities = new ArrayList<>();
    for (String rawCode : rawRecoveryCodes) {
      String codeHash = HashUtil.sha256Hex(rawCode.replace("-", "").toUpperCase());
      recoveryEntities.add(MfaRecoveryCode.builder().user(user).codeHash(codeHash).build());
    }
    recoveryCodeRepository.saveAll(recoveryEntities);

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.MFA_ENABLED,
            user.getId(),
            "SUCCESS",
            "MFA enrollment successfully completed and enabled"));

    return new MfaSetupVerificationResponse("MFA enabled successfully", rawRecoveryCodes);
  }

  public List<String> generateRecoveryCodes(int count) {
    List<String> codes = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      StringBuilder part1 = new StringBuilder(4);
      StringBuilder part2 = new StringBuilder(4);
      for (int j = 0; j < 4; j++) {
        part1.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
        part2.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
      }
      codes.add(part1.toString() + "-" + part2.toString());
    }
    return codes;
  }
}
