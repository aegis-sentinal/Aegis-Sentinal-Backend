package com.aegis.automation.domain.entity;

import com.aegis.automation.domain.model.WorkflowRunStatus;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.Workspace;
import com.aegis.investigation.domain.entity.Incident;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "workflow_runs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WorkflowRun {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "organization_id", nullable = false)
  private Organization organization;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "workspace_id")
  private Workspace workspace;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "playbook_id", nullable = false)
  private Playbook playbook;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "alert_id")
  private Alert alert;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "incident_id")
  private Incident incident;

  @Builder.Default
  @Column(nullable = false, length = 50)
  private String type = "auto_remediation";

  @Builder.Default
  @Column(nullable = false, length = 50)
  private WorkflowRunStatus status = WorkflowRunStatus.PENDING;

  @Column(name = "target_resource", nullable = false)
  private String targetResource;

  @Builder.Default
  @Column(name = "executed_by", nullable = false, length = 100)
  private String executedBy = "forge-engine";

  @Column(name = "execution_log", columnDefinition = "TEXT")
  private String executionLog;

  @Column(columnDefinition = "TEXT")
  private String result;

  @CreationTimestamp
  @Column(name = "executed_at", nullable = false, updatable = false)
  private Instant executedAt;

  @Column(name = "completed_at")
  private Instant completedAt;

  @Builder.Default
  @OneToMany(mappedBy = "workflowRun", cascade = CascadeType.ALL, orphanRemoval = true)
  private List<WorkflowApproval> approvals = new ArrayList<>();
}
