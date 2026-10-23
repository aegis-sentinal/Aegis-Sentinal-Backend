package com.aegis.automation.application.executor;

import com.aegis.automation.domain.model.ActionType;

public interface RemediationActionExecutor {

  ActionType getSupportedAction();

  default boolean supports(ActionType actionType) {
    return getSupportedAction() == actionType;
  }

  ExecutionResult execute(RemediationContext context);

  VerificationResult verify(RemediationContext context);

  ExecutionResult rollback(RemediationContext context);
}
