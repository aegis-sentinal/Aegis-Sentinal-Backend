package com.aegis.automation.application.executor;

import java.time.Instant;
import java.util.Map;
import lombok.Builder;

@Builder
public record ExecutionResult(
    boolean success,
    String executionLog,
    String summary,
    Map<String, Object> outputState,
    Instant timestamp,
    String errorMessage) {
  public static ExecutionResult successful(
      String summary, String log, Map<String, Object> outputState) {
    return ExecutionResult.builder()
        .success(true)
        .summary(summary)
        .executionLog(log)
        .outputState(outputState != null ? outputState : Map.of())
        .timestamp(Instant.now())
        .build();
  }

  public static ExecutionResult failed(String summary, String log, String errorMessage) {
    return ExecutionResult.builder()
        .success(false)
        .summary(summary)
        .executionLog(log)
        .errorMessage(errorMessage)
        .timestamp(Instant.now())
        .build();
  }
}
