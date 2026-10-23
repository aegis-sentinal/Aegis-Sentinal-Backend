package com.aegis.intelligence.api.dto;

import jakarta.validation.constraints.NotBlank;

public record ThreatLookupRequest(@NotBlank String indicator) {}
