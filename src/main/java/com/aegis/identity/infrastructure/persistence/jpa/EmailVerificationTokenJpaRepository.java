package com.aegis.identity.infrastructure.persistence.jpa;

import com.aegis.identity.domain.entity.EmailVerificationToken;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationTokenJpaRepository
    extends JpaRepository<EmailVerificationToken, UUID> {

  Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

  void deleteByUserId(UUID userId);
}
