package com.aegis.identity.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(
    description = "Response payload returned upon authentication, registration, or MFA challenge")
public record AuthenticationResponse(
    @Schema(description = "Authentication or registration status", example = "SUCCESS")
        String status,
    @Schema(
            description = "Short-lived JWT Access Token used in Authorization header",
            example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        String accessToken,
    @Schema(
            description = "Long-lived refresh token used to obtain new access tokens",
            example = "a9b8c7d6-e5f4-3210-fedc-ba9876543210")
        String refreshToken,
    @Schema(description = "OAuth2 authorization token type", example = "Bearer") String tokenType,
    @Schema(
            description = "MFA Challenge ID if MFA verification is required",
            example = "550e8400-e29b-41d4-a716-446655440000")
        String challengeId,
    @Schema(description = "Challenge expiration window in seconds", example = "300") Long expiresIn,
    @Schema(
            description = "Informational or status message",
            example = "Registration successful. Please check your email to verify your account.")
        String message) {

  public AuthenticationResponse(String accessToken, String refreshToken, String tokenType) {
    this("SUCCESS", accessToken, refreshToken, tokenType, null, null, null);
  }

  public static AuthenticationResponse mfaRequired(String challengeId, long expiresIn) {
    return new AuthenticationResponse(
        "MFA_REQUIRED", null, null, null, challengeId, expiresIn, "MFA verification required");
  }

  public static AuthenticationResponse registrationPending(String message) {
    return new AuthenticationResponse(
        "EMAIL_VERIFICATION_REQUIRED", null, null, null, null, null, message);
  }
}
