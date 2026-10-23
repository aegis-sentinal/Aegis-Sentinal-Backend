package com.aegis.automation.infrastructure.persistence.jpa;

import com.aegis.automation.domain.entity.WorkflowRun;
import com.aegis.automation.domain.model.WorkflowRunStatus;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface WorkflowRunJpaRepository
    extends JpaRepository<WorkflowRun, UUID>, JpaSpecificationExecutor<WorkflowRun> {

  long countByOrganizationId(UUID organizationId);

  long countByOrganizationIdAndStatus(UUID organizationId, WorkflowRunStatus status);
}
