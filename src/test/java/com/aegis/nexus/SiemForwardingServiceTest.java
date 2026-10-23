package com.aegis.nexus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.nexus.application.service.SiemForwardingService;
import com.aegis.nexus.domain.entity.IntegrationConnector;
import com.aegis.nexus.domain.model.IntegrationCategory;
import com.aegis.nexus.domain.model.IntegrationStatus;
import com.aegis.nexus.infrastructure.dispatch.ElasticLogstashDispatcher;
import com.aegis.nexus.infrastructure.dispatch.PagerDutyDispatcher;
import com.aegis.nexus.infrastructure.dispatch.SlackWebhookDispatcher;
import com.aegis.nexus.infrastructure.dispatch.SplunkHecDispatcher;
import com.aegis.nexus.infrastructure.persistence.IntegrationConnectorJpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SiemForwardingServiceTest {

  @Mock private IntegrationConnectorJpaRepository connectorRepository;
  @Mock private SplunkHecDispatcher splunkDispatcher;
  @Mock private ElasticLogstashDispatcher elasticDispatcher;
  @Mock private SlackWebhookDispatcher slackDispatcher;
  @Mock private PagerDutyDispatcher pagerDutyDispatcher;

  private SiemForwardingService forwardingService;

  private UUID orgId;
  private Organization testOrg;

  @BeforeEach
  void setUp() {
    forwardingService =
        new SiemForwardingService(
            connectorRepository,
            splunkDispatcher,
            elasticDispatcher,
            slackDispatcher,
            pagerDutyDispatcher);

    orgId = UUID.randomUUID();
    testOrg = Organization.builder().id(orgId).name("Acme Corp").slug("acme").build();
  }

  @Test
  @DisplayName(
      "dispatchAlertToConnectedSiems forwards alert to connected Splunk and Slack instances")
  void dispatchAlert_forwardsToActiveConnectors() {
    IntegrationConnector splunkConn =
        IntegrationConnector.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .connectorKey("splunk")
            .name("Enterprise Splunk HEC")
            .category(IntegrationCategory.SIEM)
            .status(IntegrationStatus.CONNECTED)
            .build();

    IntegrationConnector slackConn =
        IntegrationConnector.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .connectorKey("slack")
            .name("SOC Alert Channel")
            .category(IntegrationCategory.ALERTING)
            .status(IntegrationStatus.CONNECTED)
            .build();

    when(connectorRepository.findAllByOrganizationId(orgId))
        .thenReturn(List.of(splunkConn, slackConn));

    when(splunkDispatcher.dispatch(any(Alert.class), anyString(), anyString()))
        .thenReturn(new SplunkHecDispatcher.DispatchResult(true, "OK", "24ms"));
    when(slackDispatcher.dispatch(any(Alert.class), anyString(), anyString()))
        .thenReturn(new SplunkHecDispatcher.DispatchResult(true, "OK", "15ms"));

    Alert alert =
        Alert.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .title("Critical IAM Privilege Escalation")
            .description("Role assignments modified")
            .severity(AlertSeverity.CRITICAL)
            .cloudProvider(CloudProvider.AWS)
            .build();

    forwardingService.dispatchAlertToConnectedSiems(alert);

    verify(splunkDispatcher).dispatch(eq(alert), anyString(), anyString());
    verify(slackDispatcher).dispatch(eq(alert), anyString(), anyString());
  }

  @Test
  @DisplayName("testDispatch runs connectivity verification ping")
  void testDispatch_success() {
    IntegrationConnector connector =
        IntegrationConnector.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .connectorKey("splunk")
            .name("Splunk HEC")
            .category(IntegrationCategory.SIEM)
            .status(IntegrationStatus.CONNECTED)
            .build();

    when(connectorRepository.findByOrganizationIdAndConnectorKey(orgId, "splunk"))
        .thenReturn(Optional.of(connector));
    when(splunkDispatcher.dispatch(any(Alert.class), anyString(), anyString()))
        .thenReturn(
            new SplunkHecDispatcher.DispatchResult(true, "Verification successful", "18ms"));

    SplunkHecDispatcher.DispatchResult result = forwardingService.testDispatch(orgId, "splunk");

    assertThat(result).isNotNull();
    assertThat(result.success()).isTrue();
    assertThat(result.message()).contains("Verification successful");
  }
}
