package com.aegis.nexus.api.dto;

import com.aegis.nexus.domain.model.IntegrationStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateConnectorStatusRequest(
    @NotNull(message = "Status is required") IntegrationStatus status) {}
