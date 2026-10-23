package com.aegis.detection.api.controller;

import com.aegis.common.exception.BadRequestException;
import com.aegis.detection.api.dto.AlertResponse;
import com.aegis.detection.api.dto.AlertStatusUpdateRequest;
import com.aegis.detection.api.dto.DashboardMetricsResponse;
import com.aegis.detection.application.service.AlertService;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import com.aegis.detection.domain.model.CloudProvider;
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
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Alerts & Detection",
    description =
        "Endpoints for querying security alerts, updating incident status, and retrieving dashboard metrics")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/alerts")
@RequiredArgsConstructor
public class AlertController {

  private final AlertService alertService;

  @Operation(
      summary = "List security alerts",
      description =
          "Retrieves a paginated list of security alerts scoped to the active tenant organization.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Alerts retrieved successfully"),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(
            responseCode = "403",
            description = "Forbidden - requires alert:read authority",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping
  @PreAuthorize("hasAuthority('alert:read')")
  public Page<AlertResponse> getAlerts(
      @Parameter(description = "Page number (0-based)") @RequestParam(defaultValue = "0") int page,
      @Parameter(description = "Page size limit") @RequestParam(defaultValue = "20") int limit,
      @Parameter(description = "Filter by severity (critical, high, medium, low)")
          @RequestParam(required = false)
          AlertSeverity severity,
      @Parameter(description = "Filter by status (open, investigating, resolved, false_positive)")
          @RequestParam(required = false)
          AlertStatus status,
      @Parameter(description = "Filter by cloud provider (aws, azure, gcp)")
          @RequestParam(required = false)
          CloudProvider provider,
      @Parameter(description = "Text search on title, description, or resource ID")
          @RequestParam(required = false)
          String search) {

    UUID orgId = resolveOrganizationId();
    UUID wsId = resolveWorkspaceId();

    Pageable pageable = PageRequest.of(page, limit, Sort.by(Sort.Direction.DESC, "createdAt"));
    return alertService.getAlerts(orgId, wsId, severity, status, provider, search, pageable);
  }

  @Operation(
      summary = "Get alert by ID",
      description = "Retrieves details of a specific security alert.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Alert details retrieved"),
        @ApiResponse(
            responseCode = "404",
            description = "Alert not found",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('alert:read')")
  public AlertResponse getAlertById(@PathVariable UUID id) {
    UUID orgId = resolveOrganizationId();
    return alertService.getAlertById(id, orgId);
  }

  @Operation(
      summary = "Update alert status",
      description =
          "Transitions an alert status (e.g. to investigating, contained, resolved, false_positive).")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Alert status updated"),
        @ApiResponse(
            responseCode = "404",
            description = "Alert not found",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PatchMapping("/{id}/status")
  @PreAuthorize("hasAuthority('alert:write')")
  public AlertResponse updateAlertStatus(
      @PathVariable UUID id, @Valid @RequestBody AlertStatusUpdateRequest request) {
    UUID orgId = resolveOrganizationId();
    return alertService.updateAlertStatus(id, orgId, request.status(), request.notes());
  }

  @Operation(
      summary = "Get dashboard detection metrics",
      description =
          "Computes aggregate security posture metrics (total alerts, critical alerts, MTTR, threat level).")
  @GetMapping("/metrics")
  @PreAuthorize("hasAuthority('alert:read')")
  public DashboardMetricsResponse getMetrics() {
    UUID orgId = resolveOrganizationId();
    UUID wsId = resolveWorkspaceId();
    return alertService.getDashboardMetrics(orgId, wsId);
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
}
