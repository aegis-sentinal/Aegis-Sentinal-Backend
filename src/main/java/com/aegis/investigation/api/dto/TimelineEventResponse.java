package com.aegis.investigation.api.dto;

import com.aegis.investigation.domain.entity.TimelineEvent;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record TimelineEventResponse(
    UUID id,
    @JsonProperty("event_type") String eventType,
    String title,
    String description,
    String source,
    Instant timestamp) {

  public static TimelineEventResponse fromEntity(TimelineEvent event) {
    return new TimelineEventResponse(
        event.getId(),
        event.getEventType() != null ? event.getEventType().name() : "TELEMETRY_LOGGED",
        event.getTitle(),
        event.getDescription(),
        event.getSource(),
        event.getTimestamp());
  }
}
