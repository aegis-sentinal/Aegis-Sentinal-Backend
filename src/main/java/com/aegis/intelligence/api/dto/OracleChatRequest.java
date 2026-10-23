package com.aegis.intelligence.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import java.util.UUID;

public record OracleChatRequest(
    @NotBlank String prompt,
    @JsonProperty("alert_id") UUID alertId,
    @JsonProperty("incident_id") UUID incidentId) {}
