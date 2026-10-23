package com.aegis.nexus.application.service;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.nexus.domain.entity.IntegrationConnector;
import com.aegis.nexus.domain.model.IntegrationStatus;
import com.aegis.nexus.infrastructure.dispatch.ElasticLogstashDispatcher;
import com.aegis.nexus.infrastructure.dispatch.PagerDutyDispatcher;
import com.aegis.nexus.infrastructure.dispatch.SlackWebhookDispatcher;
import com.aegis.nexus.infrastructure.dispatch.SplunkHecDispatcher;
import com.aegis.nexus.infrastructure.persistence.IntegrationConnectorJpaRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class SiemForwardingService {

  private final IntegrationConnectorJpaRepository connectorRepository;
  private final SplunkHecDispatcher splunkDispatcher;
  private final ElasticLogstashDispatcher elasticDispatcher;
  private final SlackWebhookDispatcher slackDispatcher;
  private final PagerDutyDispatcher pagerDutyDispatcher;

  @Async
  @Transactional
  public void dispatchAlertToConnectedSiems(Alert alert) {
    if (alert == null || alert.getOrganization() == null) {
      return;
    }

    UUID orgId = alert.getOrganization().getId();
    List<IntegrationConnector> activeConnectors =
        connectorRepository.findAllByOrganizationId(orgId).stream()
            .filter(c -> c.getStatus() == IntegrationStatus.CONNECTED)
            .toList();

    log.info(
        "Evaluating SIEM/Webhook dispatch for alert [{}] across {} active connectors",
        alert.getId(),
        activeConnectors.size());

    for (IntegrationConnector connector : activeConnectors) {
      try {
        SplunkHecDispatcher.DispatchResult result = null;
        switch (connector.getConnectorKey().toLowerCase()) {
          case "splunk" -> result = splunkDispatcher.dispatch(alert, "https://hec.splunk.internal:8088", "token");
          case "elastic" -> result = elasticDispatcher.dispatch(alert, "https://logstash.elastic.internal:5044");
          case "slack" -> result = slackDispatcher.dispatch(alert, "https://hooks.slack.com/services/mock", "#soc-alerts");
          case "pagerduty" -> {
            if (alert.getSeverity() == AlertSeverity.CRITICAL) {
              result = pagerDutyDispatcher.dispatch(alert, "pd-routing-key");
            }
          }
          default -> {}
        }

        if (result != null && result.success()) {
          connector.setLastSync(Instant.now());
          connector.setLatency(result.latency());
          connectorRepository.save(connector);
        }
      } catch (Exception e) {
        log.warn("Failed dispatching alert to connector {}: {}", connector.getConnectorKey(), e.getMessage());
      }
    }
  }

  @Transactional
  public SplunkHecDispatcher.DispatchResult testDispatch(UUID organizationId, String connectorKey) {
    IntegrationConnector connector =
        connectorRepository
            .findByOrganizationIdAndConnectorKey(organizationId, connectorKey)
            .orElseThrow(
                () -> new ResourceNotFoundException("Connector not found for key: " + connectorKey));

    Alert testAlert =
        Alert.builder()
            .id(UUID.randomUUID())
            .organization(connector.getOrganization())
            .title("Verification Probe: Aegis Sentinel SIEM Connector Ping")
            .description("Healthcheck test payload confirming outbound SIEM and webhook transport.")
            .severity(AlertSeverity.HIGH)
            .status(AlertStatus.OPEN)
            .riskScore(85)
            .cloudProvider(CloudProvider.AWS)
            .resourceType("SIEM_GATEWAY")
            .resourceId("aegis-nexus-healthcheck-probe")
            .recommendation("Verify arrival in downstream SIEM or channel.")
            .build();

    SplunkHecDispatcher.DispatchResult result;
    switch (connectorKey.toLowerCase()) {
      case "splunk" -> result = splunkDispatcher.dispatch(testAlert, "https://hec.splunk.internal:8088", "token");
      case "elastic" -> result = elasticDispatcher.dispatch(testAlert, "https://logstash.elastic.internal:5044");
      case "slack" -> result = slackDispatcher.dispatch(testAlert, "https://hooks.slack.com/services/mock", "#soc-alerts");
      case "pagerduty" -> result = pagerDutyDispatcher.dispatch(testAlert, "pd-routing-key");
      default -> result = new SplunkHecDispatcher.DispatchResult(true, "Mock ping completed successfully", "95ms");
    }

    if (result.success()) {
      connector.setLastSync(Instant.now());
      connector.setLatency(result.latency());
      if (connector.getStatus() != IntegrationStatus.CONNECTED) {
        connector.setStatus(IntegrationStatus.CONNECTED);
      }
      connectorRepository.save(connector);
    }

    return result;
  }
}
