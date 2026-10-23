package com.aegis.intelligence.api.dto;

import com.aegis.intelligence.domain.entity.ThreatIndicator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record ThreatIndicatorResponse(
    UUID id,
    String type,
    String indicator,
    String threat,
    String severity,
    String country,
    @JsonProperty("mitre_technique") String mitreTechnique,
    @JsonProperty("confidence_score") Integer confidenceScore,
    @JsonProperty("first_seen") Instant firstSeen,
    @JsonProperty("last_seen") Instant lastSeen) {

  public static ThreatIndicatorResponse fromEntity(ThreatIndicator ti) {
    return new ThreatIndicatorResponse(
        ti.getId(),
        ti.getType(),
        ti.getIndicator(),
        ti.getThreatDescription(),
        ti.getSeverity(),
        ti.getCountry(),
        ti.getMitreTechnique(),
        ti.getConfidenceScore(),
        ti.getFirstSeen(),
        ti.getLastSeen());
  }
}
