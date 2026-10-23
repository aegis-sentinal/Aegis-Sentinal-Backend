package com.aegis.identity.infrastructure.persistence.adapter;

import com.aegis.identity.domain.entity.EmailVerificationToken;
import com.aegis.identity.domain.repository.EmailVerificationTokenRepository;
import com.aegis.identity.infrastructure.persistence.jpa.EmailVerificationTokenJpaRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class EmailVerificationTokenRepositoryAdapter implements EmailVerificationTokenRepository {

  private final EmailVerificationTokenJpaRepository repository;

  public EmailVerificationTokenRepositoryAdapter(EmailVerificationTokenJpaRepository repository) {
    this.repository = repository;
  }

  @Override
  public EmailVerificationToken save(EmailVerificationToken token) {
    return repository.save(token);
  }

  @Override
  public Optional<EmailVerificationToken> findByTokenHash(String tokenHash) {
    return repository.findByTokenHash(tokenHash);
  }

  @Override
  public void deleteByUserId(UUID userId) {
    repository.deleteByUserId(userId);
  }
}
