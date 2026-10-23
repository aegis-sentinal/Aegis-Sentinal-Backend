package com.aegis.detection.application.service;

import com.aegis.detection.api.dto.DetectionRuleResponse;
import com.aegis.detection.domain.entity.DetectionRule;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.domain.model.RuleType;
import com.aegis.detection.infrastructure.persistence.jpa.DetectionRuleJpaRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class DetectionRuleService {

  private final DetectionRuleJpaRepository detectionRuleRepository;

  @Transactional(readOnly = true)
  public List<DetectionRuleResponse> getAllRules() {
    return detectionRuleRepository.findAll().stream()
        .map(DetectionRuleResponse::fromEntity)
        .toList();
  }

  @Transactional
  public DetectionRuleResponse createRule(
      String name,
      String description,
      RuleType ruleType,
      AlertSeverity severity,
      CloudProvider cloudProvider,
      String queryPattern,
      String mitreAttackId,
      String mitreTactic,
      int riskScore) {

    DetectionRule rule =
        DetectionRule.builder()
            .name(name)
            .description(description)
            .ruleType(ruleType != null ? ruleType : RuleType.SIGMA)
            .severity(severity != null ? severity : AlertSeverity.MEDIUM)
            .cloudProvider(cloudProvider != null ? cloudProvider : CloudProvider.AWS)
            .queryPattern(queryPattern)
            .mitreAttackId(mitreAttackId)
            .mitreTactic(mitreTactic)
            .riskScore(riskScore)
            .isEnabled(true)
            .build();

    DetectionRule saved = detectionRuleRepository.save(rule);
    return DetectionRuleResponse.fromEntity(saved);
  }
}
