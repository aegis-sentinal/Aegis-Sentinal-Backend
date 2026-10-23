package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Response payload containing user MFA status")
public record MfaStatusResponse(
    @Schema(description = "Whether MFA is currently enabled for the user", example = "true")
        Boolean isMfaEnabled) {}
