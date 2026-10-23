package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MatchedSigmaRuleDto(
    @JsonProperty("id") String id,
    @JsonProperty("title") String title,
    @JsonProperty("severity") String severity,
    @JsonProperty("latencyMs") double latencyMs) {}
