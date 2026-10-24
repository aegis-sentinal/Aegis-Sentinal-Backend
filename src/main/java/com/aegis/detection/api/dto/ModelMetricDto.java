package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ModelMetricDto(
    @JsonProperty("modelName") String modelName,
    @JsonProperty("category") String category,
    @JsonProperty("architecture") String architecture,
    @JsonProperty("inferenceLatencyMs") double inferenceLatencyMs,
    @JsonProperty("accuracy") double accuracy,
    @JsonProperty("precision") double precision,
    @JsonProperty("recall") double recall,
    @JsonProperty("f1Score") double f1Score,
    @JsonProperty("anomalyScore") double anomalyScore,
    @JsonProperty("fusionWeight") double fusionWeight,
    @JsonProperty("contributionPercent") double contributionPercent,
    @JsonProperty("detectionDetails") String detectionDetails) {}
