package com.aegis.identity.infrastructure.persistence.adapter;

import com.aegis.identity.domain.entity.MfaChallenge;
import com.aegis.identity.domain.repository.MfaChallengeRepository;
import com.aegis.identity.infrastructure.persistence.jpa.MfaChallengeJpaRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class MfaChallengeRepositoryAdapter implements MfaChallengeRepository {

  private final MfaChallengeJpaRepository repository;

  public MfaChallengeRepositoryAdapter(MfaChallengeJpaRepository repository) {
    this.repository = repository;
  }

  @Override
  public MfaChallenge save(MfaChallenge challenge) {
    return repository.save(challenge);
  }

  @Override
  public Optional<MfaChallenge> findById(UUID id) {
    return repository.findById(id);
  }

  @Override
  public void deleteByUserId(UUID userId) {
    repository.deleteByUserId(userId);
  }
}
