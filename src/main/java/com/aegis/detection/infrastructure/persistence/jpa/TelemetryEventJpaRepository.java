package com.aegis.detection.infrastructure.persistence.jpa;

import com.aegis.detection.domain.entity.TelemetryEvent;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TelemetryEventJpaRepository extends JpaRepository<TelemetryEvent, UUID> {}
