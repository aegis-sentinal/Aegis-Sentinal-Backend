package com.aegis.automation.infrastructure.persistence.jpa;

import com.aegis.automation.domain.entity.WorkflowRun;
import com.aegis.automation.domain.model.WorkflowRunStatus;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;

public class WorkflowRunSpecification {

  public static Specification<WorkflowRun> filter(
      UUID organizationId, UUID workspaceId, UUID alertId, WorkflowRunStatus status) {

    return (root, query, cb) -> {
      List<Predicate> predicates = new ArrayList<>();

      predicates.add(cb.equal(root.get("organization").get("id"), organizationId));

      if (workspaceId != null) {
        predicates.add(cb.equal(root.get("workspace").get("id"), workspaceId));
      }

      if (alertId != null) {
        predicates.add(cb.equal(root.get("alert").get("id"), alertId));
      }

      if (status != null) {
        predicates.add(cb.equal(root.get("status"), status));
      }

      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }
}
