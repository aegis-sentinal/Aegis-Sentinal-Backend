package com.aegis.automation.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.automation.api.dto.ApprovalDecisionRequest;
import com.aegis.automation.api.dto.ExecuteWorkflowRequest;
import com.aegis.automation.api.dto.WorkflowResponse;
import com.aegis.automation.domain.entity.Playbook;
import com.aegis.automation.domain.entity.WorkflowApproval;
import com.aegis.automation.domain.entity.WorkflowRun;
import com.aegis.automation.domain.model.ActionType;
import com.aegis.automation.domain.model.WorkflowRunStatus;
import com.aegis.automation.infrastructure.persistence.jpa.PlaybookJpaRepository;
import com.aegis.automation.infrastructure.persistence.jpa.WorkflowApprovalJpaRepository;
import com.aegis.automation.infrastructure.persistence.jpa.WorkflowRunJpaRepository;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.infrastructure.persistence.jpa.OrganizationJpaRepository;
import com.aegis.identity.infrastructure.persistence.jpa.WorkspaceJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ForgeAutomationServiceTest {

  @Mock private PlaybookJpaRepository playbookRepository;
  @Mock private WorkflowRunJpaRepository workflowRunRepository;
  @Mock private WorkflowApprovalJpaRepository workflowApprovalRepository;
  @Mock private OrganizationJpaRepository organizationRepository;
  @Mock private WorkspaceJpaRepository workspaceRepository;
  @Mock private AlertJpaRepository alertRepository;
  @Mock private IncidentJpaRepository incidentRepository;

  private ForgeAutomationService automationService;

  private UUID orgId;
  private UUID playbookId;
  private UUID workflowRunId;
  private Organization testOrg;
  private Playbook testPlaybook;

  @BeforeEach
  void setUp() {
    automationService =
        new ForgeAutomationService(
            playbookRepository,
            workflowRunRepository,
            workflowApprovalRepository,
            organizationRepository,
            workspaceRepository,
            alertRepository,
            incidentRepository);

    orgId = UUID.randomUUID();
    playbookId = UUID.randomUUID();
    workflowRunId = UUID.randomUUID();

    testOrg =
        Organization.builder()
            .id(orgId)
            .name("Acme Corp")
            .slug("acme")
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();

    testPlaybook =
        Playbook.builder()
            .id(playbookId)
            .name("Revoke IAM Session")
            .description("Revokes active credentials")
            .actionType(ActionType.REVOKE_IAM_KEYS)
            .requiresApproval(true)
            .isEnabled(true)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();
  }

  @Test
  @DisplayName("Should initiate workflow in PENDING status when playbook requires approval")
  void shouldInitiateWorkflowPendingApproval() {
    ExecuteWorkflowRequest request =
        new ExecuteWorkflowRequest(playbookId, null, null, "arn:aws:iam::123456789012:role/admin");

    when(playbookRepository.findById(playbookId)).thenReturn(Optional.of(testPlaybook));
    when(organizationRepository.findById(orgId)).thenReturn(Optional.of(testOrg));
    when(workflowRunRepository.save(any(WorkflowRun.class)))
        .thenAnswer(
            inv -> {
              WorkflowRun run = inv.getArgument(0);
              run.setId(workflowRunId);
              return run;
            });

    WorkflowResponse response =
        automationService.initiateWorkflow(request, orgId, null, "analyst@acme.com");

    assertThat(response).isNotNull();
    assertThat(response.status()).isEqualTo("pending");
    assertThat(response.targetResource()).isEqualTo("arn:aws:iam::123456789012:role/admin");
    verify(workflowRunRepository).save(any(WorkflowRun.class));
  }

  @Test
  @DisplayName("Should approve and execute pending workflow run")
  void shouldApproveWorkflowRun() {
    WorkflowRun pendingRun =
        WorkflowRun.builder()
            .id(workflowRunId)
            .organization(testOrg)
            .playbook(testPlaybook)
            .status(WorkflowRunStatus.PENDING)
            .targetResource("arn:aws:iam::123456789012:role/admin")
            .executedBy("analyst@acme.com")
            .executedAt(Instant.now())
            .build();

    when(workflowRunRepository.findById(workflowRunId)).thenReturn(Optional.of(pendingRun));
    when(workflowRunRepository.save(any(WorkflowRun.class))).thenAnswer(inv -> inv.getArgument(0));

    ApprovalDecisionRequest decision =
        new ApprovalDecisionRequest("Authorized by lead SOC analyst");
    WorkflowResponse response =
        automationService.approveWorkflow(
            workflowRunId, decision, orgId, UUID.randomUUID(), "Lead Analyst");

    assertThat(response).isNotNull();
    assertThat(response.status()).isEqualTo("executed");
    assertThat(response.result()).contains("Approved & executed action");
    verify(workflowApprovalRepository).save(any(WorkflowApproval.class));
  }

  @Test
  @DisplayName("Should reject pending workflow run with rationale")
  void shouldRejectWorkflowRun() {
    WorkflowRun pendingRun =
        WorkflowRun.builder()
            .id(workflowRunId)
            .organization(testOrg)
            .playbook(testPlaybook)
            .status(WorkflowRunStatus.PENDING)
            .targetResource("arn:aws:iam::123456789012:role/admin")
            .executedBy("analyst@acme.com")
            .executedAt(Instant.now())
            .build();

    when(workflowRunRepository.findById(workflowRunId)).thenReturn(Optional.of(pendingRun));
    when(workflowRunRepository.save(any(WorkflowRun.class))).thenAnswer(inv -> inv.getArgument(0));

    ApprovalDecisionRequest decision =
        new ApprovalDecisionRequest("Target is legitimate deployment pipeline");
    WorkflowResponse response =
        automationService.rejectWorkflow(
            workflowRunId, decision, orgId, UUID.randomUUID(), "Lead Analyst");

    assertThat(response).isNotNull();
    assertThat(response.status()).isEqualTo("failed"); // mapped to failed/rejected in UI
    assertThat(response.result()).contains("Rejected by analyst");
    verify(workflowApprovalRepository).save(any(WorkflowApproval.class));
  }

  @Test
  @DisplayName("Should rollback executed workflow run")
  void shouldRollbackExecutedWorkflowRun() {
    WorkflowRun executedRun =
        WorkflowRun.builder()
            .id(workflowRunId)
            .organization(testOrg)
            .playbook(testPlaybook)
            .status(WorkflowRunStatus.EXECUTED)
            .targetResource("arn:aws:iam::123456789012:role/admin")
            .executedBy("analyst@acme.com")
            .executedAt(Instant.now())
            .build();

    when(workflowRunRepository.findById(workflowRunId)).thenReturn(Optional.of(executedRun));
    when(workflowRunRepository.save(any(WorkflowRun.class))).thenAnswer(inv -> inv.getArgument(0));

    WorkflowResponse response =
        automationService.rollbackWorkflow(workflowRunId, orgId, UUID.randomUUID(), "Lead Analyst");

    assertThat(response).isNotNull();
    assertThat(response.status()).isEqualTo("rolled_back");
    assertThat(response.result()).contains("Compensating rollback completed");
  }
}
