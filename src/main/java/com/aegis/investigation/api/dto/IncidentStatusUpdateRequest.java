package com.aegis.investigation.api.dto;

import com.aegis.investigation.domain.model.IncidentStatus;
import jakarta.validation.constraints.NotNull;

public record IncidentStatusUpdateRequest(@NotNull IncidentStatus status, String reason) {}
