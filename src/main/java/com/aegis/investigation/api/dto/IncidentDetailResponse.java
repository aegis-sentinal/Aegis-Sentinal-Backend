package com.aegis.investigation.api.dto;

import com.aegis.detection.api.dto.AlertResponse;
import com.aegis.investigation.domain.entity.Incident;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public record IncidentDetailResponse(
    UUID id,
    String title,
    String summary,
    String severity,
    String status,
    @JsonProperty("risk_score") Integer riskScore,
    @JsonProperty("cloud_provider") String cloudProvider,
    List<AlertResponse> alerts,
    @JsonProperty("timeline_events") List<TimelineEventResponse> timelineEvents,
    @JsonProperty("evidence_artifacts") List<EvidenceArtifactResponse> evidenceArtifacts,
    List<IncidentCommentResponse> comments,
    @JsonProperty("created_at") Instant createdAt,
    @JsonProperty("updated_at") Instant updatedAt,
    @JsonProperty("closed_at") Instant closedAt) {

  public static IncidentDetailResponse fromEntity(Incident incident) {
    List<AlertResponse> alertDtos =
        incident.getAlerts() != null
            ? incident.getAlerts().stream().map(AlertResponse::fromEntity).toList()
            : Collections.emptyList();

    List<TimelineEventResponse> timelineDtos =
        incident.getTimelineEvents() != null
            ? incident.getTimelineEvents().stream().map(TimelineEventResponse::fromEntity).toList()
            : Collections.emptyList();

    List<EvidenceArtifactResponse> artifactDtos =
        incident.getEvidenceArtifacts() != null
            ? incident.getEvidenceArtifacts().stream()
                .map(EvidenceArtifactResponse::fromEntity)
                .toList()
            : Collections.emptyList();

    List<IncidentCommentResponse> commentDtos =
        incident.getComments() != null
            ? incident.getComments().stream().map(IncidentCommentResponse::fromEntity).toList()
            : Collections.emptyList();

    return new IncidentDetailResponse(
        incident.getId(),
        incident.getTitle(),
        incident.getSummary(),
        incident.getSeverity() != null ? incident.getSeverity().getValue() : "medium",
        incident.getStatus() != null ? incident.getStatus().getValue() : "new",
        incident.getRiskScore(),
        incident.getCloudProvider() != null ? incident.getCloudProvider().getValue() : "aws",
        alertDtos,
        timelineDtos,
        artifactDtos,
        commentDtos,
        incident.getCreatedAt(),
        incident.getUpdatedAt(),
        incident.getClosedAt());
  }
}
