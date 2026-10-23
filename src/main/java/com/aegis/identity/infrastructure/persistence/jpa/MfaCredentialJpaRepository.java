package com.aegis.identity.infrastructure.persistence.jpa;

import com.aegis.identity.domain.entity.MfaCredential;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MfaCredentialJpaRepository extends JpaRepository<MfaCredential, UUID> {

  Optional<MfaCredential> findByUserId(UUID userId);

  void deleteByUserId(UUID userId);
}
