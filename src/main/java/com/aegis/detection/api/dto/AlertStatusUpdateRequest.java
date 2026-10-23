package com.aegis.detection.api.dto;

import com.aegis.detection.domain.model.AlertStatus;
import jakarta.validation.constraints.NotNull;

public record AlertStatusUpdateRequest(@NotNull AlertStatus status, String notes) {}
