package com.aegis.automation.api.dto;

import com.aegis.automation.domain.entity.Playbook;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record PlaybookResponse(
    UUID id,
    String name,
    String description,
    @JsonProperty("action_type") String actionType,
    @JsonProperty("owasp_category") String owaspCategory,
    @JsonProperty("owasp_code") String owaspCode,
    @JsonProperty("nist_phase") String nistPhase,
    @JsonProperty("compliance_ref") String complianceRef,
    @JsonProperty("requires_approval") Boolean requiresApproval,
    @JsonProperty("is_enabled") Boolean isEnabled,
    @JsonProperty("created_at") Instant createdAt) {

  public static PlaybookResponse fromEntity(Playbook playbook) {
    return new PlaybookResponse(
        playbook.getId(),
        playbook.getName(),
        playbook.getDescription(),
        playbook.getActionType() != null ? playbook.getActionType().name() : "BLOCK_IP",
        playbook.getOwaspCategory(),
        playbook.getOwaspCode(),
        playbook.getNistPhase(),
        playbook.getComplianceRef(),
        playbook.getRequiresApproval(),
        playbook.getIsEnabled(),
        playbook.getCreatedAt());
  }
}
