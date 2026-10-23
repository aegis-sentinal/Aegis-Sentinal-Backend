package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Response payload returned during MFA setup initiation")
public record MfaSetupResponse(
    @Schema(description = "Base32 encoded secret key", example = "JBSWY3DPEHPK3PXP") String secret,
    @Schema(
            description = "Standard TOTP URI for QR code generation",
            example =
                "otpauth://totp/Aegis%20Sentinel:admin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Aegis%20Sentinel")
        String otpauthUri,
    @Schema(description = "Application issuer name", example = "Aegis Sentinel") String issuer,
    @Schema(description = "User account identifier", example = "admin@example.com")
        String account) {}
