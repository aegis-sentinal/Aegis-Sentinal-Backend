package com.aegis.investigation.api.controller;

import com.aegis.common.exception.BadRequestException;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.identity.infrastructure.security.tenant.TenantContext;
import com.aegis.investigation.api.dto.IncidentCommentRequest;
import com.aegis.investigation.api.dto.IncidentCommentResponse;
import com.aegis.investigation.api.dto.IncidentDetailResponse;
import com.aegis.investigation.api.dto.IncidentResponse;
import com.aegis.investigation.api.dto.IncidentStatusUpdateRequest;
import com.aegis.investigation.application.service.IncidentService;
import com.aegis.investigation.domain.model.IncidentStatus;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Investigation & Prism",
    description =
        "Endpoints for incident management, forensic attack timelines, evidence artifacts, and case annotations")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/incidents")
@RequiredArgsConstructor
public class IncidentController {

  private final IncidentService incidentService;

  @Operation(
      summary = "List security incidents",
      description =
          "Retrieves a paginated list of security incidents scoped to the tenant organization.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Incidents retrieved"),
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
  @PreAuthorize("hasAuthority('alert:read')")
  public Page<IncidentResponse> getIncidents(
      @Parameter(description = "Page number (0-based)") @RequestParam(defaultValue = "0") int page,
      @Parameter(description = "Page size limit") @RequestParam(defaultValue = "20") int limit,
      @Parameter(description = "Filter by status (new, investigating, escalated, remediation_pending, resolved, closed)")
          @RequestParam(required = false)
          IncidentStatus status,
      @Parameter(description = "Filter by severity (critical, high, medium, low)")
          @RequestParam(required = false)
          AlertSeverity severity,
      @Parameter(description = "Search title or summary") @RequestParam(required = false)
          String search) {

    UUID orgId = resolveOrganizationId();
    UUID wsId = resolveWorkspaceId();

    Pageable pageable = PageRequest.of(page, limit, Sort.by(Sort.Direction.DESC, "createdAt"));
    return incidentService.getIncidents(orgId, wsId, status, severity, search, pageable);
  }

  @Operation(
      summary = "Get incident details and forensic timeline",
      description =
          "Retrieves full incident dossier including correlated alerts, chronological timeline events, and evidence artifacts.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Incident dossier retrieved"),
        @ApiResponse(
            responseCode = "404",
            description = "Incident not found",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('alert:read')")
  public IncidentDetailResponse getIncidentDetail(@PathVariable UUID id) {
    UUID orgId = resolveOrganizationId();
    return incidentService.getIncidentDetail(id, orgId);
  }

  @Operation(
      summary = "Update incident lifecycle status",
      description =
          "Transitions an incident state (e.g. to investigating, escalated, resolved, closed) and appends a timeline transition entry.")
  @PatchMapping("/{id}/status")
  @PreAuthorize("hasAuthority('alert:write')")
  public IncidentResponse updateIncidentStatus(
      @PathVariable UUID id, @Valid @RequestBody IncidentStatusUpdateRequest request) {
    UUID orgId = resolveOrganizationId();
    UUID userId = resolveUserId();
    return incidentService.updateIncidentStatus(
        id, orgId, request.status(), request.reason(), userId);
  }

  @Operation(
      summary = "Add analyst annotation comment",
      description = "Appends an analyst note to the incident and registers it in the timeline.")
  @PostMapping("/{id}/comments")
  @ResponseStatus(HttpStatus.CREATED)
  @PreAuthorize("hasAuthority('alert:write')")
  public IncidentCommentResponse addComment(
      @PathVariable UUID id, @Valid @RequestBody IncidentCommentRequest request) {
    UUID orgId = resolveOrganizationId();
    UUID userId = resolveUserId();
    return incidentService.addComment(id, orgId, request.message(), userId, "SOC Analyst");
  }

  private UUID resolveOrganizationId() {
    TenantContext context = TenantContext.get();
    if (context == null || context.organizationId() == null) {
      throw new BadRequestException("Organization tenant context could not be resolved from headers or token.");
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
}
