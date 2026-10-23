package com.aegis.automation.api.dto;

import com.aegis.automation.domain.entity.WorkflowRun;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record WorkflowResponse(
    UUID id,
    @JsonProperty("alert_id") UUID alertId,
    String type,
    String status,
    @JsonProperty("executed_at") Instant executedAt,
    @JsonProperty("executed_by") String executedBy,
    String description,
    String result,
    @JsonProperty("owasp_category") String owaspCategory,
    @JsonProperty("owasp_code") String owaspCode,
    @JsonProperty("nist_phase") String nistPhase,
    @JsonProperty("compliance_ref") String complianceRef,
    @JsonProperty("target_resource") String targetResource,
    @JsonProperty("execution_log") String executionLog) {

  public static WorkflowResponse fromEntity(WorkflowRun run) {
    return new WorkflowResponse(
        run.getId(),
        run.getAlert() != null ? run.getAlert().getId() : null,
        run.getType(),
        run.getStatus() != null ? run.getStatus().getValue() : "pending",
        run.getExecutedAt(),
        run.getExecutedBy(),
        run.getPlaybook() != null
            ? run.getPlaybook().getDescription()
            : "Automated remediation action",
        run.getResult(),
        run.getPlaybook() != null ? run.getPlaybook().getOwaspCategory() : null,
        run.getPlaybook() != null ? run.getPlaybook().getOwaspCode() : null,
        run.getPlaybook() != null ? run.getPlaybook().getNistPhase() : null,
        run.getPlaybook() != null ? run.getPlaybook().getComplianceRef() : null,
        run.getTargetResource(),
        run.getExecutionLog());
  }
}
