package com.aegis.identity.infrastructure.persistence.jpa;

import com.aegis.identity.domain.entity.MfaChallenge;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MfaChallengeJpaRepository extends JpaRepository<MfaChallenge, UUID> {

  void deleteByUserId(UUID userId);
}
