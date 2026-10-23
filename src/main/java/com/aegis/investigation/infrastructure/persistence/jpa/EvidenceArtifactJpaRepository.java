package com.aegis.investigation.infrastructure.persistence.jpa;

import com.aegis.investigation.domain.entity.EvidenceArtifact;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EvidenceArtifactJpaRepository extends JpaRepository<EvidenceArtifact, UUID> {

  List<EvidenceArtifact> findByIncidentId(UUID incidentId);
}
