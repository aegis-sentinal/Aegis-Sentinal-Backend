package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TelemetryAnalysisRequest(
    @NotBlank(message = "Log content cannot be empty")
    @JsonProperty("log_content")
    String logContent,

    @JsonProperty("pipeline_type")
    String pipelineType) {}
