package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Request payload for email verification")
public record VerifyEmailRequest(
    @Schema(
            description = "Raw email verification token",
            example = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        @NotBlank(message = "Token must not be blank")
        String token) {}
