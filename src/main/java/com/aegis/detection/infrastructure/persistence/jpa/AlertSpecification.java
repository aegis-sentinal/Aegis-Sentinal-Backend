package com.aegis.detection.infrastructure.persistence.jpa;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import com.aegis.detection.domain.model.CloudProvider;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;

public class AlertSpecification {

  public static Specification<Alert> filter(
      UUID organizationId,
      UUID workspaceId,
      AlertSeverity severity,
      AlertStatus status,
      CloudProvider cloudProvider,
      String search) {

    return (root, query, cb) -> {
      List<Predicate> predicates = new ArrayList<>();

      predicates.add(cb.equal(root.get("organization").get("id"), organizationId));

      if (workspaceId != null) {
        predicates.add(cb.equal(root.get("workspace").get("id"), workspaceId));
      }

      if (severity != null) {
        predicates.add(cb.equal(root.get("severity"), severity));
      }

      if (status != null) {
        predicates.add(cb.equal(root.get("status"), status));
      }

      if (cloudProvider != null) {
        predicates.add(cb.equal(root.get("cloudProvider"), cloudProvider));
      }

      if (search != null && !search.trim().isEmpty()) {
        String likePattern = "%" + search.trim().toLowerCase() + "%";
        Predicate searchPredicate =
            cb.or(
                cb.like(cb.lower(root.get("title")), likePattern),
                cb.like(cb.lower(root.get("description")), likePattern),
                cb.like(cb.lower(root.get("resourceId")), likePattern));
        predicates.add(searchPredicate);
      }

      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }
}
