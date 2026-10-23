package com.aegis.automation.application.executor;

import static org.assertj.core.api.Assertions.assertThat;

import com.aegis.automation.application.executor.aws.AwsIamRevocationExecutor;
import com.aegis.automation.application.executor.aws.AwsS3BucketBlockExecutor;
import com.aegis.automation.application.executor.aws.AwsSecurityGroupIsolationExecutor;
import com.aegis.automation.application.executor.k8s.KubernetesQuarantineExecutor;
import com.aegis.automation.domain.model.ActionType;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ForgeRemediationExecutorsTest {

  @Test
  @DisplayName("AwsIamRevocationExecutor executes session revocation and passes verification")
  void iamExecutor_executeAndVerify() {
    AwsIamRevocationExecutor executor = new AwsIamRevocationExecutor();
    assertThat(executor.supports(ActionType.REVOKE_IAM_KEYS)).isTrue();

    RemediationContext context =
        RemediationContext.builder()
            .workflowRunId(UUID.randomUUID())
            .organizationId(UUID.randomUUID())
            .targetResource("arn:aws:iam::123456789012:user/compromised-admin")
            .actionType("REVOKE_IAM_KEYS")
            .executedBy("soc-analyst")
            .parameters(Map.of())
            .stateSnapshot(Map.of())
            .build();

    ExecutionResult execResult = executor.execute(context);
    assertThat(execResult.success()).isTrue();
    assertThat(execResult.summary()).contains("Successfully deactivated IAM access keys");

    VerificationResult verifyResult = executor.verify(context);
    assertThat(verifyResult.verified()).isTrue();
    assertThat(verifyResult.verificationProof()).contains("VERIFIED");

    ExecutionResult rollbackResult = executor.rollback(context);
    assertThat(rollbackResult.success()).isTrue();
    assertThat(rollbackResult.summary()).contains("Compensating rollback complete");
  }

  @Test
  @DisplayName("AwsS3BucketBlockExecutor locks down public access and verifies configuration")
  void s3Executor_executeAndVerify() {
    AwsS3BucketBlockExecutor executor = new AwsS3BucketBlockExecutor();
    assertThat(executor.supports(ActionType.BLOCK_S3_PUBLIC)).isTrue();

    RemediationContext context =
        RemediationContext.builder()
            .workflowRunId(UUID.randomUUID())
            .organizationId(UUID.randomUUID())
            .targetResource("arn:aws:s3:::prod-customer-data")
            .actionType("BLOCK_S3_PUBLIC")
            .executedBy("soc-analyst")
            .parameters(Map.of())
            .stateSnapshot(Map.of())
            .build();

    ExecutionResult execResult = executor.execute(context);
    assertThat(execResult.success()).isTrue();
    assertThat(execResult.summary()).contains("Successfully enforced Public Access Block");

    VerificationResult verifyResult = executor.verify(context);
    assertThat(verifyResult.verified()).isTrue();

    ExecutionResult rollbackResult = executor.rollback(context);
    assertThat(rollbackResult.success()).isTrue();
  }

  @Test
  @DisplayName("KubernetesQuarantineExecutor applies network isolation policy to pod")
  void k8sExecutor_executeAndVerify() {
    KubernetesQuarantineExecutor executor = new KubernetesQuarantineExecutor();
    assertThat(executor.supports(ActionType.QUARANTINE_K8S_POD)).isTrue();

    RemediationContext context =
        RemediationContext.builder()
            .workflowRunId(UUID.randomUUID())
            .organizationId(UUID.randomUUID())
            .targetResource("k8s:default:pod/crypto-miner-7f99")
            .actionType("K8S_QUARANTINE_POD")
            .executedBy("soc-analyst")
            .parameters(Map.of())
            .stateSnapshot(Map.of())
            .build();

    ExecutionResult execResult = executor.execute(context);
    assertThat(execResult.success()).isTrue();
    assertThat(execResult.summary()).contains("Successfully isolated workload");

    VerificationResult verifyResult = executor.verify(context);
    assertThat(verifyResult.verified()).isTrue();
  }
}
