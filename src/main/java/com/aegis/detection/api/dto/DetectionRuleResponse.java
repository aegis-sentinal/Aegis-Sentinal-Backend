package com.aegis.detection.api.dto;

import com.aegis.detection.domain.entity.DetectionRule;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

public record DetectionRuleResponse(
    UUID id,
    String name,
    String description,
    @JsonProperty("rule_type") String ruleType,
    String severity,
    @JsonProperty("cloud_provider") String cloudProvider,
    @JsonProperty("query_pattern") String queryPattern,
    @JsonProperty("mitre_attack_id") String mitreAttackId,
    @JsonProperty("mitre_tactic") String mitreTactic,
    @JsonProperty("risk_score") Integer riskScore,
    @JsonProperty("is_enabled") Boolean isEnabled) {

  public static DetectionRuleResponse fromEntity(DetectionRule rule) {
    return new DetectionRuleResponse(
        rule.getId(),
        rule.getName(),
        rule.getDescription(),
        rule.getRuleType() != null ? rule.getRuleType().name() : "SIGMA",
        rule.getSeverity() != null ? rule.getSeverity().getValue() : "medium",
        rule.getCloudProvider() != null ? rule.getCloudProvider().getValue() : "aws",
        rule.getQueryPattern(),
        rule.getMitreAttackId(),
        rule.getMitreTactic(),
        rule.getRiskScore(),
        rule.getIsEnabled());
  }
}
