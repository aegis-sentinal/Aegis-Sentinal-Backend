package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Schema(description = "Request payload to confirm MFA setup")
public record MfaVerifySetupRequest(
    @Schema(description = "6-digit TOTP code from authenticator app", example = "123456")
        @NotBlank(message = "Code must not be blank")
        @Pattern(regexp = "^\\d{6}$", message = "Code must be a 6-digit number")
        String code) {}
