package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Request payload to regenerate recovery codes")
public record MfaRegenerateCodesRequest(
    @Schema(description = "Current 6-digit TOTP code for authentication", example = "123456")
        @NotBlank(message = "Code must not be blank")
        String code) {}
