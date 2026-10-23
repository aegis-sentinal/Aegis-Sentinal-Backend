package com.aegis.automation.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record ExecuteWorkflowRequest(
    @NotNull @JsonProperty("playbook_id") UUID playbookId,
    @JsonProperty("alert_id") UUID alertId,
    @JsonProperty("incident_id") UUID incidentId,
    @NotBlank @JsonProperty("target_resource") String targetResource) {}
