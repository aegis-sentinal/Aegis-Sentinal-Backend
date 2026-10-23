package com.aegis.audit.api.controller;

import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.application.service.AuditLogService;
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
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Compliance & Audit Logs",
    description =
        "Endpoints for querying tenant-scoped immutable audit events, actor actions, and SHA-256 integrity locks")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/audit-logs")
@RequiredArgsConstructor
public class AuditLogController {

  private final AuditLogService auditLogService;

  @Operation(
      summary = "Query immutable audit logs",
      description =
          "Retrieves a paginated list of compliance audit events scoped to the tenant organization.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Audit logs retrieved"),
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
  @PreAuthorize("hasAnyAuthority('audit:read', 'org:manage')")
  public Page<AuditLogResponse> getAuditLogs(
      @Parameter(description = "Page number (0-based)") @RequestParam(defaultValue = "0") int page,
      @Parameter(description = "Page size limit") @RequestParam(defaultValue = "50") int limit,
      @Parameter(description = "Filter by actor name or email") @RequestParam(required = false)
          String actor,
      @Parameter(description = "Filter by action keyword") @RequestParam(required = false)
          String action,
      @Parameter(description = "Filter by result (SUCCESS, FAILURE, PARTIAL)")
          @RequestParam(required = false)
          String result) {

    UUID orgId = resolveOrganizationId();
    Pageable pageable = PageRequest.of(page, limit, Sort.by(Sort.Direction.DESC, "timestamp"));
    return auditLogService.getAuditLogs(orgId, actor, action, result, pageable);
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
