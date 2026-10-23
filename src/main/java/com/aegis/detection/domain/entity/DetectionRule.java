package com.aegis.detection.domain.entity;

import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.domain.model.RuleType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "detection_rules")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DetectionRule {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(nullable = false)
  private String name;

  @Column(columnDefinition = "TEXT")
  private String description;

  @Enumerated(EnumType.STRING)
  @Column(name = "rule_type", nullable = false, length = 50)
  private RuleType ruleType;

  @Column(nullable = false, length = 20)
  private AlertSeverity severity;

  @Builder.Default
  @Column(name = "cloud_provider", nullable = false, length = 50)
  private CloudProvider cloudProvider = CloudProvider.AWS;

  @Column(name = "query_pattern", nullable = false, columnDefinition = "TEXT")
  private String queryPattern;

  @Column(name = "mitre_attack_id", length = 50)
  private String mitreAttackId;

  @Column(name = "mitre_tactic", length = 100)
  private String mitreTactic;

  @Builder.Default
  @Column(name = "risk_score", nullable = false)
  private Integer riskScore = 50;

  @Builder.Default
  @Column(name = "is_enabled", nullable = false)
  private Boolean isEnabled = true;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;
}
