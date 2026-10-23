package com.aegis.detection.infrastructure.persistence.jpa;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AlertJpaRepository
    extends JpaRepository<Alert, UUID>, JpaSpecificationExecutor<Alert> {

  long countByOrganizationId(UUID organizationId);

  long countByOrganizationIdAndSeverity(UUID organizationId, AlertSeverity severity);

  long countByOrganizationIdAndStatus(UUID organizationId, AlertStatus status);

  @Query(
      "SELECT a FROM Alert a WHERE a.organization.id = :orgId AND (:workspaceId IS NULL OR"
          + " a.workspace.id = :workspaceId)")
  Page<Alert> findByOrgAndOptionalWorkspace(
      @Param("orgId") UUID orgId, @Param("workspaceId") UUID workspaceId, Pageable pageable);
}
