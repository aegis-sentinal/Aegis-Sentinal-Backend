package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ExtractedEntitiesDto(
    @JsonProperty("principal") String principal,
    @JsonProperty("sourceIp") String sourceIp,
    @JsonProperty("targetResource") String targetResource,
    @JsonProperty("eventAction") String eventAction,
    @JsonProperty("geoCountry") String geoCountry,
    @JsonProperty("anomalyIndicators") List<String> anomalyIndicators) {}
