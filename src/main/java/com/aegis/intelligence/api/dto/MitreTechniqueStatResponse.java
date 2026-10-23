package com.aegis.intelligence.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MitreTechniqueStatResponse(
    String code, String name, String category, @JsonProperty("threat_count") Long threatCount) {}
