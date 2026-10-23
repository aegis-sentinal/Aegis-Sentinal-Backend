package com.aegis.investigation.api.dto;

import com.aegis.investigation.domain.entity.IncidentComment;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record IncidentCommentResponse(
    UUID id,
    @JsonProperty("author_id") UUID authorId,
    @JsonProperty("author_name") String authorName,
    String message,
    @JsonProperty("created_at") Instant createdAt) {

  public static IncidentCommentResponse fromEntity(IncidentComment comment) {
    return new IncidentCommentResponse(
        comment.getId(),
        comment.getAuthorId(),
        comment.getAuthorName(),
        comment.getMessage(),
        comment.getCreatedAt());
  }
}
