package com.aegis.detection.api.controller;

import com.aegis.common.exception.BadRequestException;
import com.aegis.detection.api.dto.TelemetryIngestRequest;
import com.aegis.detection.api.dto.TelemetryIngestResponse;
import com.aegis.detection.application.service.TelemetryIngestionService;
import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.identity.infrastructure.security.tenant.TenantContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Telemetry Ingestion",
    description =
        "Endpoints for streaming raw cloud telemetry (CloudTrail, GuardDuty, VPC Flow, K8s) into the Sentinel Core detection engine")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/telemetry")
@RequiredArgsConstructor
public class TelemetryController {

  private final TelemetryIngestionService telemetryIngestionService;

  @Operation(
      summary = "Ingest cloud telemetry event",
      description =
          "Receives a raw telemetry event from AWS/Azure/GCP/Kubernetes, persists it, and evaluates it against active detection rules.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "201", description = "Telemetry processed successfully"),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid payload or missing tenant context",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/ingest")
  @ResponseStatus(HttpStatus.CREATED)
  @PreAuthorize("hasAuthority('alert:write')")
  public TelemetryIngestResponse ingestTelemetry(
      @Valid @RequestBody TelemetryIngestRequest request) {

    TenantContext context = TenantContext.get();
    if (context == null || context.organizationId() == null) {
      throw new BadRequestException(
          "Organization tenant context required for telemetry ingestion.");
    }

    UUID orgId = context.organizationId();
    UUID wsId = context.workspaceId();

    return telemetryIngestionService.ingest(request, orgId, wsId);
  }

  @Operation(
      summary = "Ingest Azure Activity Logs & Entra ID telemetry",
      description =
          "Parses and normalizes Azure Monitor Activity Logs, evaluating them against Azure detection rules.")
  @PostMapping("/azure")
  @ResponseStatus(HttpStatus.CREATED)
  @PreAuthorize("hasAuthority('alert:write')")
  public java.util.List<TelemetryIngestResponse> ingestAzureTelemetry(
      @RequestBody java.util.Map<String, Object> payload) {
    TenantContext context = TenantContext.get();
    if (context == null || context.organizationId() == null) {
      throw new BadRequestException(
          "Organization tenant context required for telemetry ingestion.");
    }
    return telemetryIngestionService.ingestAzure(
        payload, context.organizationId(), context.workspaceId());
  }

  @Operation(
      summary = "Ingest GCP Cloud Audit Logs & Pub/Sub telemetry",
      description =
          "Parses and normalizes GCP Cloud Audit Logs, evaluating them against GCP detection rules.")
  @PostMapping("/gcp")
  @ResponseStatus(HttpStatus.CREATED)
  @PreAuthorize("hasAuthority('alert:write')")
  public java.util.List<TelemetryIngestResponse> ingestGcpTelemetry(
      @RequestBody java.util.Map<String, Object> payload) {
    TenantContext context = TenantContext.get();
    if (context == null || context.organizationId() == null) {
      throw new BadRequestException(
          "Organization tenant context required for telemetry ingestion.");
    }
    return telemetryIngestionService.ingestGcp(
        payload, context.organizationId(), context.workspaceId());
  }
}
