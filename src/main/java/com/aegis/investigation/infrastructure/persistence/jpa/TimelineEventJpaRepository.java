package com.aegis.investigation.infrastructure.persistence.jpa;

import com.aegis.investigation.domain.entity.TimelineEvent;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TimelineEventJpaRepository extends JpaRepository<TimelineEvent, UUID> {

  List<TimelineEvent> findByIncidentIdOrderByTimestampAsc(UUID incidentId);
}
