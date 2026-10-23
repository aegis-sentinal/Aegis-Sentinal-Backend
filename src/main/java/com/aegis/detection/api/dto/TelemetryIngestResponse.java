package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

public record TelemetryIngestResponse(
    @JsonProperty("telemetry_id") UUID telemetryId,
    boolean matched,
    @JsonProperty("alert_id") UUID alertId,
    String message) {}
