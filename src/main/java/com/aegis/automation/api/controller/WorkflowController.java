package com.aegis.automation.api.controller;

import com.aegis.automation.api.dto.ApprovalDecisionRequest;
import com.aegis.automation.api.dto.ExecuteWorkflowRequest;
import com.aegis.automation.api.dto.PlaybookResponse;
import com.aegis.automation.api.dto.WorkflowResponse;
import com.aegis.automation.application.service.ForgeAutomationService;
import com.aegis.automation.domain.model.WorkflowRunStatus;
import com.aegis.common.exception.BadRequestException;
import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.identity.infrastructure.security.tenant.TenantContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Automation & Forge",
    description =
        "SOAR playbooks, human-in-the-loop approval gates, workflow execution, and compensating rollback")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/workflows")
@RequiredArgsConstructor
public class WorkflowController {

  private final ForgeAutomationService automationService;

  @Operation(
      summary = "List workflow runs",
      description =
          "Retrieves a paginated audit log of automated and manual workflow execution runs.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Workflows retrieved"),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(
            responseCode = "403",
            description = "Forbidden",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping
  @PreAuthorize("hasAnyAuthority('alert:read', 'workflow:execute')")
  public Page<WorkflowResponse> getWorkflows(
      @Parameter(description = "Page number (0-based)") @RequestParam(defaultValue = "0") int page,
      @Parameter(description = "Page size limit") @RequestParam(defaultValue = "20") int limit,
      @Parameter(description = "Filter by associated alert ID") @RequestParam(required = false)
          UUID alertId,
      @Parameter(description = "Filter by workflow run status") @RequestParam(required = false)
          WorkflowRunStatus status) {

    UUID orgId = resolveOrganizationId();
    UUID wsId = resolveWorkspaceId();

    Pageable pageable = PageRequest.of(page, limit, Sort.by(Sort.Direction.DESC, "executedAt"));
    return automationService.getWorkflowRuns(orgId, wsId, alertId, status, pageable);
  }

  @Operation(
      summary = "List SOAR playbooks",
      description = "Retrieves available pre-approved remediation playbooks.")
  @GetMapping("/playbooks")
  @PreAuthorize("hasAnyAuthority('alert:read', 'workflow:execute')")
  public List<PlaybookResponse> getPlaybooks() {
    return automationService.getPlaybooks();
  }

  @Operation(
      summary = "Get workflow run detail",
      description = "Retrieves detailed execution state, parameters, and logs for a workflow run.")
  @GetMapping("/{id}")
  @PreAuthorize("hasAnyAuthority('alert:read', 'workflow:execute')")
  public WorkflowResponse getWorkflowById(@PathVariable UUID id) {
    UUID orgId = resolveOrganizationId();
    return automationService.getWorkflowRunById(id, orgId);
  }

  @Operation(
      summary = "Initiate workflow execution",
      description =
          "Submits a playbook for execution. If the playbook requires approval, it is queued in PENDING status.")
  @PostMapping("/execute")
  @ResponseStatus(HttpStatus.ACCEPTED)
  @PreAuthorize("hasAuthority('workflow:execute')")
  public WorkflowResponse executeWorkflow(@Valid @RequestBody ExecuteWorkflowRequest request) {
    UUID orgId = resolveOrganizationId();
    UUID wsId = resolveWorkspaceId();
    String actorName = resolveActorName();

    return automationService.initiateWorkflow(request, orgId, wsId, actorName);
  }

  @Operation(
      summary = "Approve pending workflow run",
      description =
          "Fulfills the human approval gate requirement (AS-PRD-001) and executes the remediation action.")
  @PostMapping("/{id}/approve")
  @PreAuthorize("hasAuthority('workflow:execute')")
  public WorkflowResponse approveWorkflow(
      @PathVariable UUID id, @RequestBody(required = false) ApprovalDecisionRequest request) {
    UUID orgId = resolveOrganizationId();
    UUID userId = resolveUserId();
    String actorName = resolveActorName();

    return automationService.approveWorkflow(id, request, orgId, userId, actorName);
  }

  @Operation(
      summary = "Reject pending workflow run",
      description = "Rejects a pending remediation action with an analyst rationale.")
  @PostMapping("/{id}/reject")
  @PreAuthorize("hasAuthority('workflow:execute')")
  public WorkflowResponse rejectWorkflow(
      @PathVariable UUID id, @RequestBody(required = false) ApprovalDecisionRequest request) {
    UUID orgId = resolveOrganizationId();
    UUID userId = resolveUserId();
    String actorName = resolveActorName();

    return automationService.rejectWorkflow(id, request, orgId, userId, actorName);
  }

  @Operation(
      summary = "Rollback executed workflow run",
      description =
          "Executes a compensating transaction to undo the previously applied remediation action.")
  @PostMapping("/{id}/rollback")
  @PreAuthorize("hasAuthority('workflow:execute')")
  public WorkflowResponse rollbackWorkflow(@PathVariable UUID id) {
    UUID orgId = resolveOrganizationId();
    UUID userId = resolveUserId();
    String actorName = resolveActorName();

    return automationService.rollbackWorkflow(id, orgId, userId, actorName);
  }

  private UUID resolveOrganizationId() {
    TenantContext context = TenantContext.get();
    if (context == null || context.organizationId() == null) {
      throw new BadRequestException(
          "Organization tenant context could not be resolved from headers or token.");
    }
    return context.organizationId();
  }

  private UUID resolveWorkspaceId() {
    TenantContext context = TenantContext.get();
    return context != null ? context.workspaceId() : null;
  }

  private UUID resolveUserId() {
    TenantContext context = TenantContext.get();
    return context != null ? context.userId() : null;
  }

  private String resolveActorName() {
    TenantContext context = TenantContext.get();
    return context != null && context.userId() != null
        ? "Analyst (" + context.userId() + ")"
        : "SOC Analyst";
  }
}
