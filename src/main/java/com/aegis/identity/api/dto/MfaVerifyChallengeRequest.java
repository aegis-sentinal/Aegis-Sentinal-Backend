package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.UUID;

@Schema(description = "Request payload to verify an active MFA login challenge")
public record MfaVerifyChallengeRequest(
    @Schema(
            description = "MFA Challenge ID issued during login",
            example = "550e8400-e29b-41d4-a716-446655440000")
        @NotNull(message = "Challenge ID must not be null")
        UUID challengeId,
    @Schema(description = "6-digit TOTP code", example = "123456")
        @NotNull(message = "Code must not be null")
        @Pattern(regexp = "^\\d{6}$", message = "Code must be a 6-digit number")
        String code) {}
