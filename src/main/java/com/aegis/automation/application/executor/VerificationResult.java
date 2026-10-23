package com.aegis.automation.application.executor;

import java.time.Instant;
import java.util.Map;
import lombok.Builder;

@Builder
public record VerificationResult(
    boolean verified,
    String verificationProof,
    String details,
    Map<String, Object> observedState,
    Instant timestamp) {
  public static VerificationResult passed(String proof, String details, Map<String, Object> state) {
    return VerificationResult.builder()
        .verified(true)
        .verificationProof(proof)
        .details(details)
        .observedState(state != null ? state : Map.of())
        .timestamp(Instant.now())
        .build();
  }

  public static VerificationResult failed(String reason, Map<String, Object> state) {
    return VerificationResult.builder()
        .verified(false)
        .verificationProof(
            "FAILED: Target resource state check did not meet remediation assertions.")
        .details(reason)
        .observedState(state != null ? state : Map.of())
        .timestamp(Instant.now())
        .build();
  }
}
