package com.aegis.automation.domain.entity;

import com.aegis.automation.domain.model.ApprovalDecision;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "workflow_approvals")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WorkflowApproval {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "workflow_run_id", nullable = false)
  private WorkflowRun workflowRun;

  @Column(name = "decided_by")
  private UUID decidedBy;

  @Column(name = "decided_by_name", length = 100)
  private String decidedByName;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private ApprovalDecision decision;

  @Column(columnDefinition = "TEXT")
  private String reason;

  @CreationTimestamp
  @Column(name = "decided_at", nullable = false, updatable = false)
  private Instant decidedAt;
}
