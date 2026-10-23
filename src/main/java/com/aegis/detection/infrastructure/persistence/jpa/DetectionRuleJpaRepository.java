package com.aegis.detection.infrastructure.persistence.jpa;

import com.aegis.detection.domain.entity.DetectionRule;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DetectionRuleJpaRepository extends JpaRepository<DetectionRule, UUID> {

  List<DetectionRule> findByIsEnabledTrue();
}
