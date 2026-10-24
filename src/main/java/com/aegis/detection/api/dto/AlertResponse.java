package com.aegis.detection.api.dto;

import com.aegis.detection.domain.entity.Alert;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public record AlertResponse(
    UUID id,
    String title,
    String description,
    String severity,
    @JsonProperty("risk_score") Integer riskScore,
    String status,
    @JsonProperty("cloud_provider") String cloudProvider,
    @JsonProperty("resource_type") String resourceType,
    @JsonProperty("resource_id") String resourceId,
    @JsonProperty("affected_services") List<String> affectedServices,
    String recommendation,
    @JsonProperty("retry_attempts") Integer retryAttempts,
    @JsonProperty("created_at") Instant createdAt,
    @JsonProperty("updated_at") Instant updatedAt) {

  public static AlertResponse fromEntity(Alert alert) {
    List<String> services;
    if (alert.getAffectedServices() != null) {
      services = new java.util.ArrayList<>();
      for (String service : alert.getAffectedServices().split(",")) {
        String trimmed = service.trim();
        if (!trimmed.isEmpty()) {
          services.add(trimmed);
        }
      }
    } else {
      services = Collections.emptyList();
    }

    return new AlertResponse(
        alert.getId(),
        alert.getTitle(),
        alert.getDescription(),
        alert.getSeverity() != null ? alert.getSeverity().getValue() : "medium",
        alert.getRiskScore(),
        alert.getStatus() != null ? alert.getStatus().getValue() : "open",
        alert.getCloudProvider() != null ? alert.getCloudProvider().getValue() : "aws",
        alert.getResourceType(),
        alert.getResourceId(),
        services,
        alert.getRecommendation(),
        alert.getRetryAttempts(),
        alert.getCreatedAt(),
        alert.getUpdatedAt());
  }
}
