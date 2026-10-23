package com.aegis.identity.infrastructure.persistence.jpa;

import com.aegis.identity.domain.entity.MfaRecoveryCode;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MfaRecoveryCodeJpaRepository extends JpaRepository<MfaRecoveryCode, UUID> {

  @Query("SELECT r FROM MfaRecoveryCode r WHERE r.user.id = :userId AND r.usedAt IS NULL")
  List<MfaRecoveryCode> findUnusedByUserId(@Param("userId") UUID userId);

  void deleteByUserId(UUID userId);
}
