package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record TelemetryIngestRequest(
    @JsonProperty("event_id") String eventId,
    @NotBlank @JsonProperty("event_source") String eventSource,
    @NotBlank @JsonProperty("event_name") String eventName,
    @JsonProperty("principal_id") String principalId,
    @JsonProperty("source_ip") String sourceIp,
    @JsonProperty("destination_resource") String destinationResource,
    @JsonProperty("cloud_provider") String cloudProvider,
    @JsonProperty("raw_payload") Map<String, Object> rawPayload) {}
