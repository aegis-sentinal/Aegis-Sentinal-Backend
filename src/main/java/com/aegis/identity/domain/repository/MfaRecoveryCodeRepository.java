package com.aegis.identity.domain.repository;

import com.aegis.identity.domain.entity.MfaRecoveryCode;
import java.util.List;
import java.util.UUID;

public interface MfaRecoveryCodeRepository {

  MfaRecoveryCode save(MfaRecoveryCode recoveryCode);

  List<MfaRecoveryCode> saveAll(List<MfaRecoveryCode> recoveryCodes);

  List<MfaRecoveryCode> findUnusedByUserId(UUID userId);

  void deleteByUserId(UUID userId);
}
