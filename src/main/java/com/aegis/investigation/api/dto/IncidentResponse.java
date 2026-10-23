package com.aegis.investigation.api.dto;

import com.aegis.investigation.domain.entity.Incident;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record IncidentResponse(
    UUID id,
    String title,
    String summary,
    String severity,
    String status,
    @JsonProperty("risk_score") Integer riskScore,
    @JsonProperty("cloud_provider") String cloudProvider,
    @JsonProperty("alert_count") int alertCount,
    @JsonProperty("created_at") Instant createdAt,
    @JsonProperty("updated_at") Instant updatedAt,
    @JsonProperty("closed_at") Instant closedAt) {

  public static IncidentResponse fromEntity(Incident incident) {
    return new IncidentResponse(
        incident.getId(),
        incident.getTitle(),
        incident.getSummary(),
        incident.getSeverity() != null ? incident.getSeverity().getValue() : "medium",
        incident.getStatus() != null ? incident.getStatus().getValue() : "new",
        incident.getRiskScore(),
        incident.getCloudProvider() != null ? incident.getCloudProvider().getValue() : "aws",
        incident.getAlerts() != null ? incident.getAlerts().size() : 0,
        incident.getCreatedAt(),
        incident.getUpdatedAt(),
        incident.getClosedAt());
  }
}
