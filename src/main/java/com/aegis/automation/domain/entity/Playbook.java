package com.aegis.automation.domain.entity;

import com.aegis.automation.domain.model.ActionType;
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
@Table(name = "playbooks")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Playbook {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(nullable = false)
  private String name;

  @Column(columnDefinition = "TEXT")
  private String description;

  @Enumerated(EnumType.STRING)
  @Column(name = "action_type", nullable = false, length = 50)
  private ActionType actionType;

  @Column(name = "owasp_category", length = 100)
  private String owaspCategory;

  @Column(name = "owasp_code", length = 50)
  private String owaspCode;

  @Column(name = "nist_phase", length = 100)
  private String nistPhase;

  @Column(name = "compliance_ref", length = 100)
  private String complianceRef;

  @Builder.Default
  @Column(name = "requires_approval", nullable = false)
  private Boolean requiresApproval = true;

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
