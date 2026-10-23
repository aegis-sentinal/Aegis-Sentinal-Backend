package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(description = "Response payload returned upon successful MFA enrollment confirmation")
public record MfaSetupVerificationResponse(
    @Schema(description = "Confirmation message", example = "MFA enabled successfully")
        String message,
    @Schema(
            description = "10 single-use recovery codes. Save these in a safe place.",
            example = "[\"A8KD-92LX\", \"P7QM-41TZ\"]")
        List<String> recoveryCodes) {}
