package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Request payload to disable MFA")
public record MfaDisableRequest(
    @Schema(
            description = "Current user account password for re-authentication",
            example = "P@ssw0rd123!")
        @NotBlank(message = "Password must not be blank")
        String password,
    @Schema(description = "Current 6-digit TOTP code", example = "123456")
        @NotBlank(message = "Code must not be blank")
        String code) {}
