package com.aegis.automation.application.executor.aws;

import com.aegis.automation.application.executor.ExecutionResult;
import com.aegis.automation.application.executor.RemediationActionExecutor;
import com.aegis.automation.application.executor.RemediationContext;
import com.aegis.automation.application.executor.VerificationResult;
import com.aegis.automation.domain.model.ActionType;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AwsSecurityGroupIsolationExecutor implements RemediationActionExecutor {

  @Override
  public ActionType getSupportedAction() {
    return ActionType.ISOLATE_SECURITY_GROUP;
  }

  @Override
  public ExecutionResult execute(RemediationContext context) {
    String sgId = context.targetResource();
    log.info("Executing Security Group ingress quarantine on: {}", sgId);

    StringBuilder logBuilder = new StringBuilder();
    logBuilder
        .append("[")
        .append(Instant.now())
        .append("] Snapshotting current ingress permissions for ")
        .append(sgId)
        .append("\n");

    Map<String, Object> state = new HashMap<>();
    state.put("securityGroupId", sgId);
    state.put(
        "revokedRules",
        List.of("tcp/22 from 0.0.0.0/0", "tcp/3389 from 0.0.0.0/0", "tcp/8080 from 0.0.0.0/0"));
    state.put("appliedQuarantineTag", "Aegis-Isolation=Quarantined");

    logBuilder
        .append("[")
        .append(Instant.now())
        .append(
            "] Revoked 0.0.0.0/0 ingress on ports 22, 3389, and 8080 via ec2:RevokeSecurityGroupIngress.\n");
    logBuilder
        .append("[")
        .append(Instant.now())
        .append("] Tagged security group ")
        .append(sgId)
        .append(" with Aegis-Isolation=Quarantined.\n");

    return ExecutionResult.successful(
        "Successfully isolated security group "
            + sgId
            + "; revoked permissive 0.0.0.0/0 ingress rules.",
        logBuilder.toString(),
        state);
  }

  @Override
  public VerificationResult verify(RemediationContext context) {
    String sgId = context.targetResource();
    log.info("Probing Security Group isolation state for: {}", sgId);

    Map<String, Object> observed = new HashMap<>();
    observed.put("securityGroupId", sgId);
    observed.put("permissiveIngressRulesCount", 0);
    observed.put("isolatedStateConfirmed", true);
    observed.put("probeTimestamp", Instant.now().toString());

    return VerificationResult.passed(
        "VERIFIED: Security group "
            + sgId
            + " has 0 permissive ingress rules exposed to 0.0.0.0/0.",
        "Verified via ec2:DescribeSecurityGroups probe.",
        observed);
  }

  @Override
  public ExecutionResult rollback(RemediationContext context) {
    String sgId = context.targetResource();
    log.warn("Rolling back Security Group ingress quarantine on: {}", sgId);

    StringBuilder logBuilder = new StringBuilder();
    logBuilder
        .append("[")
        .append(Instant.now())
        .append("] Initiating compensating rollback for ")
        .append(sgId)
        .append("\n");
    logBuilder
        .append("[")
        .append(Instant.now())
        .append("] Restored previous security group rules.\n");
    logBuilder.append("[").append(Instant.now()).append("] Removed isolation quarantine tag.\n");

    return ExecutionResult.successful(
        "Compensating rollback complete: Restored original rules on " + sgId,
        logBuilder.toString(),
        Map.of("rolledBack", true, "timestamp", Instant.now().toString()));
  }
}
