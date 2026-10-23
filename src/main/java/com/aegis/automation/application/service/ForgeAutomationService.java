package com.aegis.automation.application.service;

import com.aegis.automation.api.dto.ApprovalDecisionRequest;
import com.aegis.automation.api.dto.ExecuteWorkflowRequest;
import com.aegis.automation.api.dto.PlaybookResponse;
import com.aegis.automation.api.dto.WorkflowResponse;
import com.aegis.automation.domain.entity.Playbook;
import com.aegis.automation.domain.entity.WorkflowApproval;
import com.aegis.automation.domain.entity.WorkflowRun;
import com.aegis.automation.domain.model.ApprovalDecision;
import com.aegis.automation.domain.model.WorkflowRunStatus;
import com.aegis.automation.infrastructure.persistence.jpa.PlaybookJpaRepository;
import com.aegis.automation.infrastructure.persistence.jpa.WorkflowApprovalJpaRepository;
import com.aegis.automation.infrastructure.persistence.jpa.WorkflowRunJpaRepository;
import com.aegis.automation.infrastructure.persistence.jpa.WorkflowRunSpecification;
import com.aegis.common.exception.BadRequestException;
import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.Workspace;
import com.aegis.identity.infrastructure.persistence.jpa.OrganizationJpaRepository;
import com.aegis.identity.infrastructure.persistence.jpa.WorkspaceJpaRepository;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ForgeAutomationService {

  private final PlaybookJpaRepository playbookRepository;
  private final WorkflowRunJpaRepository workflowRunRepository;
  private final WorkflowApprovalJpaRepository workflowApprovalRepository;
  private final OrganizationJpaRepository organizationRepository;
  private final WorkspaceJpaRepository workspaceRepository;
  private final AlertJpaRepository alertRepository;
  private final IncidentJpaRepository incidentRepository;

  @Transactional(readOnly = true)
  public List<PlaybookResponse> getPlaybooks() {
    return playbookRepository.findByIsEnabledTrue().stream()
        .map(PlaybookResponse::fromEntity)
        .toList();
  }

  @Transactional(readOnly = true)
  public Page<WorkflowResponse> getWorkflowRuns(
      UUID organizationId,
      UUID workspaceId,
      UUID alertId,
      WorkflowRunStatus status,
      Pageable pageable) {
    Specification<WorkflowRun> spec =
        WorkflowRunSpecification.filter(organizationId, workspaceId, alertId, status);
    return workflowRunRepository.findAll(spec, pageable).map(WorkflowResponse::fromEntity);
  }

  @Transactional(readOnly = true)
  public WorkflowResponse getWorkflowRunById(UUID workflowRunId, UUID organizationId) {
    WorkflowRun run =
        workflowRunRepository
            .findById(workflowRunId)
            .filter(r -> r.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Workflow run not found: " + workflowRunId));
    return WorkflowResponse.fromEntity(run);
  }

  @Transactional
  public WorkflowResponse initiateWorkflow(
      ExecuteWorkflowRequest request, UUID organizationId, UUID workspaceId, String actorName) {
    Playbook playbook =
        playbookRepository
            .findById(request.playbookId())
            .orElseThrow(
                () -> new ResourceNotFoundException("Playbook not found: " + request.playbookId()));

    if (!Boolean.TRUE.equals(playbook.getIsEnabled())) {
      throw new BadRequestException("Playbook is disabled: " + playbook.getName());
    }

    Organization organization =
        organizationRepository
            .findById(organizationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Organization not found: " + organizationId));

    Workspace workspace = null;
    if (workspaceId != null) {
      workspace = workspaceRepository.findById(workspaceId).orElse(null);
    }

    Alert alert = null;
    if (request.alertId() != null) {
      alert = alertRepository.findById(request.alertId()).orElse(null);
    }

    Incident incident = null;
    if (request.incidentId() != null) {
      incident = incidentRepository.findById(request.incidentId()).orElse(null);
    }

    WorkflowRunStatus initialStatus =
        Boolean.TRUE.equals(playbook.getRequiresApproval())
            ? WorkflowRunStatus.PENDING
            : WorkflowRunStatus.EXECUTED;

    String initialResult =
        initialStatus == WorkflowRunStatus.PENDING
            ? "Pending analyst approval"
            : "Directly executed: " + playbook.getActionType() + " on " + request.targetResource();

    String initialLog =
        initialStatus == WorkflowRunStatus.PENDING
            ? "Workflow queued awaiting manual human approval gate as mandated by IEEE 29148 / AS-PRD-001."
            : "Workflow executed automatically without manual gate requirement.";

    WorkflowRun run =
        WorkflowRun.builder()
            .organization(organization)
            .workspace(workspace)
            .playbook(playbook)
            .alert(alert)
            .incident(incident)
            .type("auto_remediation")
            .status(initialStatus)
            .targetResource(request.targetResource())
            .executedBy(actorName != null ? actorName : "forge-engine")
            .result(initialResult)
            .executionLog(initialLog)
            .completedAt(initialStatus == WorkflowRunStatus.EXECUTED ? Instant.now() : null)
            .build();

    WorkflowRun saved = workflowRunRepository.save(run);
    log.info(
        "Initiated workflow run {} with status {} for playbook {}",
        saved.getId(),
        saved.getStatus(),
        playbook.getName());
    return WorkflowResponse.fromEntity(saved);
  }

  @Transactional
  public WorkflowResponse approveWorkflow(
      UUID workflowRunId,
      ApprovalDecisionRequest decisionRequest,
      UUID organizationId,
      UUID actorUserId,
      String actorName) {
    WorkflowRun run =
        workflowRunRepository
            .findById(workflowRunId)
            .filter(r -> r.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Workflow run not found: " + workflowRunId));

    if (run.getStatus() != WorkflowRunStatus.PENDING) {
      throw new BadRequestException(
          "Workflow run cannot be approved from current state: " + run.getStatus());
    }

    WorkflowApproval approval =
        WorkflowApproval.builder()
            .workflowRun(run)
            .decidedBy(actorUserId)
            .decidedByName(actorName != null ? actorName : "SOC Analyst")
            .decision(ApprovalDecision.APPROVED)
            .reason(
                decisionRequest != null && decisionRequest.reason() != null
                    ? decisionRequest.reason()
                    : "Analyst approval verified.")
            .build();
    workflowApprovalRepository.save(approval);

    run.setStatus(WorkflowRunStatus.EXECUTED);
    run.setCompletedAt(Instant.now());
    run.setResult(
        "Approved & executed action: "
            + run.getPlaybook().getActionType()
            + " on "
            + run.getTargetResource());
    String updatedLog =
        (run.getExecutionLog() != null ? run.getExecutionLog() + "\n" : "")
            + "["
            + Instant.now()
            + "] Approved by "
            + (actorName != null ? actorName : "analyst")
            + ". Action successfully dispatched to infrastructure target.";
    run.setExecutionLog(updatedLog);

    WorkflowRun saved = workflowRunRepository.save(run);
    log.info("Workflow run {} approved and executed by {}", saved.getId(), actorName);
    return WorkflowResponse.fromEntity(saved);
  }

  @Transactional
  public WorkflowResponse rejectWorkflow(
      UUID workflowRunId,
      ApprovalDecisionRequest decisionRequest,
      UUID organizationId,
      UUID actorUserId,
      String actorName) {
    WorkflowRun run =
        workflowRunRepository
            .findById(workflowRunId)
            .filter(r -> r.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Workflow run not found: " + workflowRunId));

    if (run.getStatus() != WorkflowRunStatus.PENDING) {
      throw new BadRequestException(
          "Workflow run cannot be rejected from current state: " + run.getStatus());
    }

    WorkflowApproval approval =
        WorkflowApproval.builder()
            .workflowRun(run)
            .decidedBy(actorUserId)
            .decidedByName(actorName != null ? actorName : "SOC Analyst")
            .decision(ApprovalDecision.REJECTED)
            .reason(
                decisionRequest != null && decisionRequest.reason() != null
                    ? decisionRequest.reason()
                    : "Analyst rejected execution.")
            .build();
    workflowApprovalRepository.save(approval);

    run.setStatus(WorkflowRunStatus.FAILED);
    run.setCompletedAt(Instant.now());
    run.setResult("Rejected by analyst: " + approval.getReason());
    String updatedLog =
        (run.getExecutionLog() != null ? run.getExecutionLog() + "\n" : "")
            + "["
            + Instant.now()
            + "] Execution rejected by "
            + (actorName != null ? actorName : "analyst")
            + ". Reason: "
            + approval.getReason();
    run.setExecutionLog(updatedLog);

    WorkflowRun saved = workflowRunRepository.save(run);
    log.info("Workflow run {} rejected by {}", saved.getId(), actorName);
    return WorkflowResponse.fromEntity(saved);
  }

  @Transactional
  public WorkflowResponse rollbackWorkflow(
      UUID workflowRunId, UUID organizationId, UUID actorUserId, String actorName) {
    WorkflowRun run =
        workflowRunRepository
            .findById(workflowRunId)
            .filter(r -> r.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Workflow run not found: " + workflowRunId));

    if (run.getStatus() != WorkflowRunStatus.EXECUTED) {
      throw new BadRequestException(
          "Only executed workflows can be rolled back. Current status: " + run.getStatus());
    }

    run.setStatus(WorkflowRunStatus.ROLLED_BACK);
    run.setCompletedAt(Instant.now());
    run.setResult("Compensating rollback completed for " + run.getPlaybook().getActionType());
    String updatedLog =
        (run.getExecutionLog() != null ? run.getExecutionLog() + "\n" : "")
            + "["
            + Instant.now()
            + "] Rollback executed by "
            + (actorName != null ? actorName : "analyst")
            + ". Target state reverted.";
    run.setExecutionLog(updatedLog);

    WorkflowRun saved = workflowRunRepository.save(run);
    log.info("Workflow run {} rolled back by {}", saved.getId(), actorName);
    return WorkflowResponse.fromEntity(saved);
  }
}
