package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

@Schema(description = "Request payload for MFA recovery code login authentication")
public record MfaRecoveryRequest(
    @Schema(
            description = "MFA Challenge ID issued during login",
            example = "550e8400-e29b-41d4-a716-446655440000")
        @NotNull(message = "Challenge ID must not be null")
        UUID challengeId,
    @Schema(description = "Single-use recovery code", example = "A8KD-92LX")
        @NotBlank(message = "Recovery code must not be blank")
        String recoveryCode) {}
