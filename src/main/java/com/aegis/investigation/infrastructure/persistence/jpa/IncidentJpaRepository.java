package com.aegis.investigation.infrastructure.persistence.jpa;

import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.domain.model.IncidentStatus;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface IncidentJpaRepository
    extends JpaRepository<Incident, UUID>, JpaSpecificationExecutor<Incident> {

  long countByOrganizationId(UUID organizationId);

  long countByOrganizationIdAndStatus(UUID organizationId, IncidentStatus status);

  @Query(
      "SELECT i FROM Incident i WHERE i.organization.id = :orgId AND i.status IN ('NEW',"
          + " 'INVESTIGATING', 'ESCALATED', 'REMEDIATION_PENDING') ORDER BY i.createdAt DESC")
  Page<Incident> findActiveIncidents(@Param("orgId") UUID orgId, Pageable pageable);

  @Query("SELECT i FROM Incident i JOIN i.alerts a WHERE a.id = :alertId")
  Optional<Incident> findByAlertId(@Param("alertId") UUID alertId);
}
