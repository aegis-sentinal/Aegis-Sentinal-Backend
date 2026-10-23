package com.aegis.investigation.infrastructure.persistence.jpa;

import com.aegis.investigation.domain.entity.IncidentComment;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IncidentCommentJpaRepository extends JpaRepository<IncidentComment, UUID> {

  List<IncidentComment> findByIncidentIdOrderByCreatedAtAsc(UUID incidentId);
}
