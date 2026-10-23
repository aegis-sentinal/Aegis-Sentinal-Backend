package com.aegis.investigation.api.dto;

import jakarta.validation.constraints.NotBlank;

public record IncidentCommentRequest(@NotBlank String message) {}
