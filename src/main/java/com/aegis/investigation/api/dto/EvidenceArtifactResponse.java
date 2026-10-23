package com.aegis.investigation.api.dto;

import com.aegis.investigation.domain.entity.EvidenceArtifact;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record EvidenceArtifactResponse(
    UUID id,
    String name,
    @JsonProperty("artifact_type") String artifactType,
    @JsonProperty("content_type") String contentType,
    String checksum,
    @JsonProperty("storage_uri") String storageUri,
    @JsonProperty("created_at") Instant createdAt) {

  public static EvidenceArtifactResponse fromEntity(EvidenceArtifact artifact) {
    return new EvidenceArtifactResponse(
        artifact.getId(),
        artifact.getName(),
        artifact.getArtifactType() != null ? artifact.getArtifactType().name() : "LOG_RECORD",
        artifact.getContentType(),
        artifact.getChecksum(),
        artifact.getStorageUri(),
        artifact.getCreatedAt());
  }
}
