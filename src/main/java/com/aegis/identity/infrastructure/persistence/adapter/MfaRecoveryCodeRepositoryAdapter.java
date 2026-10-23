package com.aegis.identity.infrastructure.persistence.adapter;

import com.aegis.identity.domain.entity.MfaRecoveryCode;
import com.aegis.identity.domain.repository.MfaRecoveryCodeRepository;
import com.aegis.identity.infrastructure.persistence.jpa.MfaRecoveryCodeJpaRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class MfaRecoveryCodeRepositoryAdapter implements MfaRecoveryCodeRepository {

  private final MfaRecoveryCodeJpaRepository repository;

  public MfaRecoveryCodeRepositoryAdapter(MfaRecoveryCodeJpaRepository repository) {
    this.repository = repository;
  }

  @Override
  public MfaRecoveryCode save(MfaRecoveryCode recoveryCode) {
    return repository.save(recoveryCode);
  }

  @Override
  public List<MfaRecoveryCode> saveAll(List<MfaRecoveryCode> recoveryCodes) {
    return repository.saveAll(recoveryCodes);
  }

  @Override
  public List<MfaRecoveryCode> findUnusedByUserId(UUID userId) {
    return repository.findUnusedByUserId(userId);
  }

  @Override
  public void deleteByUserId(UUID userId) {
    repository.deleteByUserId(userId);
  }
}
