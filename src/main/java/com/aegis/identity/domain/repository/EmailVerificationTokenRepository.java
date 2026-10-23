package com.aegis.identity.domain.repository;

import com.aegis.identity.domain.entity.EmailVerificationToken;
import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenRepository {

  EmailVerificationToken save(EmailVerificationToken token);

  Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

  void deleteByUserId(UUID userId);
}
