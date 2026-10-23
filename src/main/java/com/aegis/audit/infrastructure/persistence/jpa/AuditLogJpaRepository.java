package com.aegis.audit.infrastructure.persistence.jpa;

import com.aegis.audit.domain.entity.AuditLog;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditLogJpaRepository extends JpaRepository<AuditLog, UUID> {

  @Query(
      "SELECT a FROM AuditLog a WHERE a.organization.id = :organizationId AND "
          + "(:actor IS NULL OR LOWER(a.actor) LIKE LOWER(CONCAT('%', :actor, '%'))) AND "
          + "(:action IS NULL OR LOWER(a.action) LIKE LOWER(CONCAT('%', :action, '%'))) AND "
          + "(:result IS NULL OR LOWER(a.result) = LOWER(:result))")
  Page<AuditLog> searchAuditLogs(
      @Param("organizationId") UUID organizationId,
      @Param("actor") String actor,
      @Param("action") String action,
      @Param("result") String result,
      Pageable pageable);

  List<AuditLog> findAllByOrganizationIdOrderByTimestampDesc(UUID organizationId);
}
