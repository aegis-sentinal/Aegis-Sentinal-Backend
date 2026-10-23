package com.aegis.identity.application.service;

import com.aegis.identity.api.dto.MfaSetupResponse;
import com.aegis.identity.application.port.TotpService;
import com.aegis.identity.domain.entity.MfaCredential;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaCredentialRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import com.aegis.identity.infrastructure.security.mfa.SecretEncryptionService;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaSetupService {

  private final MfaCredentialRepository mfaCredentialRepository;
  private final TotpService totpService;
  private final SecretEncryptionService encryptionService;
  private final SecurityAuditLogger auditLogger;
  private final String issuer;

  public MfaSetupService(
      MfaCredentialRepository mfaCredentialRepository,
      TotpService totpService,
      SecretEncryptionService encryptionService,
      SecurityAuditLogger auditLogger,
      @Value("${aegis.security.mfa.issuer:Aegis Sentinel}") String issuer) {
    this.mfaCredentialRepository = mfaCredentialRepository;
    this.totpService = totpService;
    this.encryptionService = encryptionService;
    this.auditLogger = auditLogger;
    this.issuer = issuer;
  }

  @Transactional
  public MfaSetupResponse execute(User user) {
    String rawSecret = totpService.generateSecret();
    String encryptedSecret = encryptionService.encrypt(rawSecret);

    Optional<MfaCredential> existingOpt = mfaCredentialRepository.findByUserId(user.getId());
    MfaCredential credential;
    if (existingOpt.isPresent()) {
      credential = existingOpt.get();
      credential.setEncryptedSecret(encryptedSecret);
      credential.setEnabledAt(null);
    } else {
      credential =
          MfaCredential.builder()
              .user(user)
              .encryptedSecret(encryptedSecret)
              .algorithm("SHA1")
              .digits(6)
              .period(30)
              .build();
    }

    mfaCredentialRepository.save(credential);

    String otpauthUri = totpService.generateOtpAuthUri(issuer, user.getEmail(), rawSecret);

    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.MFA_SETUP_STARTED, user.getId(), "SUCCESS", "MFA enrollment initiated"));

    return new MfaSetupResponse(rawSecret, otpauthUri, issuer, user.getEmail());
  }
}
