package com.aegis.automation.application.executor;

import java.util.Map;
import java.util.UUID;
import lombok.Builder;

@Builder
public record RemediationContext(
    UUID workflowRunId,
    UUID organizationId,
    String targetResource,
    String actionType,
    String executedBy,
    Map<String, Object> parameters,
    Map<String, Object> stateSnapshot) {}
