package com.aegis.investigation.infrastructure.persistence.jpa;

import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.domain.model.IncidentStatus;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;

public class IncidentSpecification {

  public static Specification<Incident> filter(
      UUID organizationId,
      UUID workspaceId,
      IncidentStatus status,
      AlertSeverity severity,
      String search) {

    return (root, query, cb) -> {
      List<Predicate> predicates = new ArrayList<>();

      predicates.add(cb.equal(root.get("organization").get("id"), organizationId));

      if (workspaceId != null) {
        predicates.add(cb.equal(root.get("workspace").get("id"), workspaceId));
      }

      if (status != null) {
        predicates.add(cb.equal(root.get("status"), status));
      }

      if (severity != null) {
        predicates.add(cb.equal(root.get("severity"), severity));
      }

      if (search != null && !search.trim().isEmpty()) {
        String likePattern = "%" + search.trim().toLowerCase() + "%";
        Predicate searchPredicate =
            cb.or(
                cb.like(cb.lower(root.get("title")), likePattern),
                cb.like(cb.lower(root.get("summary")), likePattern));
        predicates.add(searchPredicate);
      }

      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }
}
