package com.aegis.identity.infrastructure.persistence.adapter;

import com.aegis.identity.domain.entity.MfaCredential;
import com.aegis.identity.domain.repository.MfaCredentialRepository;
import com.aegis.identity.infrastructure.persistence.jpa.MfaCredentialJpaRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class MfaCredentialRepositoryAdapter implements MfaCredentialRepository {

  private final MfaCredentialJpaRepository repository;

  public MfaCredentialRepositoryAdapter(MfaCredentialJpaRepository repository) {
    this.repository = repository;
  }

  @Override
  public MfaCredential save(MfaCredential credential) {
    return repository.save(credential);
  }

  @Override
  public Optional<MfaCredential> findByUserId(UUID userId) {
    return repository.findByUserId(userId);
  }

  @Override
  public void deleteByUserId(UUID userId) {
    repository.deleteByUserId(userId);
  }
}
