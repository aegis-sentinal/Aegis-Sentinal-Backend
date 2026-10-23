package com.aegis.detection.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.detection.api.dto.AlertResponse;
import com.aegis.detection.api.dto.DashboardMetricsResponse;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

  @Mock private AlertJpaRepository alertRepository;

  private AlertService alertService;

  private UUID orgId;
  private UUID alertId;
  private Organization testOrg;
  private Alert testAlert;

  @BeforeEach
  void setUp() {
    alertService = new AlertService(alertRepository);
    orgId = UUID.randomUUID();
    alertId = UUID.randomUUID();

    testOrg = Organization.builder().id(orgId).name("Acme Corp").slug("acme").build();

    testAlert =
        Alert.builder()
            .id(alertId)
            .organization(testOrg)
            .title("Root Account Console Login")
            .description("Console login without MFA detected")
            .severity(AlertSeverity.CRITICAL)
            .status(AlertStatus.OPEN)
            .riskScore(95)
            .cloudProvider(CloudProvider.AWS)
            .resourceType("AWS::IAM::User")
            .resourceId("root")
            .affectedServices("IAM, CloudTrail")
            .recommendation("Rotate credentials immediately")
            .retryAttempts(0)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();
  }

  @Test
  @DisplayName("getAlertById returns alert response when alert belongs to org")
  void getAlertById_success() {
    when(alertRepository.findById(alertId)).thenReturn(Optional.of(testAlert));

    AlertResponse response = alertService.getAlertById(alertId, orgId);

    assertThat(response).isNotNull();
    assertThat(response.id()).isEqualTo(alertId);
    assertThat(response.title()).isEqualTo("Root Account Console Login");
    assertThat(response.severity()).isEqualTo("critical");
    assertThat(response.status()).isEqualTo("open");
  }

  @Test
  @DisplayName("updateAlertStatus transitions alert status and updates notes")
  void updateAlertStatus_success() {
    when(alertRepository.findById(alertId)).thenReturn(Optional.of(testAlert));
    when(alertRepository.save(any(Alert.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    AlertResponse response =
        alertService.updateAlertStatus(
            alertId,
            orgId,
            AlertStatus.RESOLVED,
            "Investigated and verified legitimate root login");

    assertThat(response.status()).isEqualTo("resolved");
    verify(alertRepository).save(testAlert);
  }

  @Test
  @DisplayName("getDashboardMetrics calculates correct metrics count")
  void getDashboardMetrics_success() {
    when(alertRepository.countByOrganizationId(orgId)).thenReturn(10L);
    when(alertRepository.countByOrganizationIdAndSeverity(orgId, AlertSeverity.CRITICAL))
        .thenReturn(2L);
    when(alertRepository.countByOrganizationIdAndStatus(orgId, AlertStatus.OPEN)).thenReturn(5L);
    when(alertRepository.countByOrganizationIdAndStatus(orgId, AlertStatus.RESOLVED))
        .thenReturn(3L);

    DashboardMetricsResponse metrics = alertService.getDashboardMetrics(orgId, null);

    assertThat(metrics.totalAlerts()).isEqualTo(10L);
    assertThat(metrics.criticalAlerts()).isEqualTo(2L);
    assertThat(metrics.openAlerts()).isEqualTo(5L);
    assertThat(metrics.resolvedAlerts()).isEqualTo(3L);
    assertThat(metrics.threatLevel()).isEqualTo("elevated");
  }
}
