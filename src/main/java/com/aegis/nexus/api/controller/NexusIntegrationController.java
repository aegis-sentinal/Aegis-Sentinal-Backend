package com.aegis.nexus.api.controller;

import com.aegis.common.exception.BadRequestException;
import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.identity.infrastructure.security.tenant.TenantContext;
import com.aegis.nexus.api.dto.IntegrationConnectorResponse;
import com.aegis.nexus.api.dto.UpdateConnectorStatusRequest;
import com.aegis.nexus.application.service.NexusIntegrationService;
import com.aegis.nexus.domain.model.IntegrationCategory;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Nexus & Multi-Cloud Integrations",
    description =
        "Endpoints for managing cloud telemetry connectors (AWS, Azure, GCP, K8s) and notification/SOAR dispatchers")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/nexus/integrations")
@RequiredArgsConstructor
public class NexusIntegrationController {

  private final NexusIntegrationService nexusIntegrationService;

  @Operation(
      summary = "List multi-cloud and third-party integration connectors",
      description =
          "Retrieves all configured connectors scoped to the tenant organization, optionally filtered by category.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Integration connectors retrieved"),
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
  @PreAuthorize("hasAnyAuthority('alert:read', 'org:manage')")
  public List<IntegrationConnectorResponse> getConnectors(
      @Parameter(description = "Filter by integration category (CLOUD, ALERTING, TICKETING, SIEM)")
          @RequestParam(required = false)
          IntegrationCategory category) {

    UUID orgId = resolveOrganizationId();
    return nexusIntegrationService.getConnectors(orgId, category);
  }

  @Operation(
      summary = "Get integration connector by key",
      description = "Retrieves details and health status for a specific connector key.")
  @GetMapping("/{key}")
  @PreAuthorize("hasAnyAuthority('alert:read', 'org:manage')")
  public IntegrationConnectorResponse getConnectorByKey(@PathVariable String key) {
    UUID orgId = resolveOrganizationId();
    return nexusIntegrationService.getConnectorByKey(orgId, key);
  }

  @Operation(
      summary = "Update integration connector status",
      description = "Connects or disconnects a cloud ingestion or notification dispatcher.")
  @PatchMapping("/{key}/status")
  @PreAuthorize("hasAuthority('org:manage')")
  public IntegrationConnectorResponse updateStatus(
      @PathVariable String key, @Valid @RequestBody UpdateConnectorStatusRequest request) {
    UUID orgId = resolveOrganizationId();
    return nexusIntegrationService.updateStatus(orgId, key, request);
  }

  @Operation(
      summary = "Test integration connection health",
      description = "Pings the external provider API or endpoint to verify latency and sync state.")
  @PostMapping("/{key}/test")
  @PreAuthorize("hasAuthority('org:manage')")
  public IntegrationConnectorResponse testConnection(@PathVariable String key) {
    UUID orgId = resolveOrganizationId();
    return nexusIntegrationService.testConnection(orgId, key);
  }

  private UUID resolveOrganizationId() {
    TenantContext context = TenantContext.get();
    if (context == null || context.organizationId() == null) {
      throw new BadRequestException(
          "Organization tenant context could not be resolved from headers or token.");
    }
    return context.organizationId();
  }
}
