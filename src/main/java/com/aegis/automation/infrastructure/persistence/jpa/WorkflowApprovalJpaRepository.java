package com.aegis.automation.infrastructure.persistence.jpa;

import com.aegis.automation.domain.entity.WorkflowApproval;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WorkflowApprovalJpaRepository extends JpaRepository<WorkflowApproval, UUID> {

  List<WorkflowApproval> findByWorkflowRunId(UUID workflowRunId);
}
