package com.aegis.identity.application.query;

import java.util.UUID;

public record LoginExecutionResult(
    String status, AuthenticationResult authenticationResult, UUID challengeId, Long expiresIn) {

  public static LoginExecutionResult success(AuthenticationResult authResult) {
    return new LoginExecutionResult("SUCCESS", authResult, null, null);
  }

  public static LoginExecutionResult mfaRequired(UUID challengeId, long expiresIn) {
    return new LoginExecutionResult("MFA_REQUIRED", null, challengeId, expiresIn);
  }
}
