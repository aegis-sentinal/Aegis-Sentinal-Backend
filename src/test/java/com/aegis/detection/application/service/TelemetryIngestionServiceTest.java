package com.aegis.detection.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.detection.api.dto.TelemetryIngestRequest;
import com.aegis.detection.api.dto.TelemetryIngestResponse;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.entity.DetectionRule;
import com.aegis.detection.domain.entity.TelemetryEvent;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.domain.model.RuleType;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.detection.infrastructure.persistence.jpa.DetectionRuleJpaRepository;
import com.aegis.detection.infrastructure.persistence.jpa.TelemetryEventJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.infrastructure.persistence.jpa.OrganizationJpaRepository;
import com.aegis.identity.infrastructure.persistence.jpa.WorkspaceJpaRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TelemetryIngestionServiceTest {

  @Mock private TelemetryEventJpaRepository telemetryEventRepository;
  @Mock private DetectionRuleJpaRepository detectionRuleRepository;
  @Mock private AlertJpaRepository alertRepository;
  @Mock private OrganizationJpaRepository organizationRepository;
  @Mock private WorkspaceJpaRepository workspaceRepository;
  @Mock private com.aegis.investigation.application.service.IncidentService incidentService;
  @Mock private com.aegis.detection.application.parser.AzureActivityLogParser azureParser;
  @Mock private com.aegis.detection.application.parser.GcpCloudAuditLogParser gcpParser;

  @Mock
  private com.aegis.intelligence.infrastructure.persistence.jpa.ThreatIndicatorJpaRepository
      threatIndicatorRepository;

  @Mock private com.aegis.nexus.application.service.SiemForwardingService siemForwardingService;

  private TelemetryIngestionService ingestionService;

  private UUID orgId;
  private Organization testOrg;
  private DetectionRule rootLoginRule;

  @BeforeEach
  void setUp() {
    ingestionService =
        new TelemetryIngestionService(
            telemetryEventRepository,
            detectionRuleRepository,
            alertRepository,
            organizationRepository,
            workspaceRepository,
            new ObjectMapper(),
            incidentService,
            azureParser,
            gcpParser,
            threatIndicatorRepository,
            siemForwardingService);

    orgId = UUID.randomUUID();
    testOrg = Organization.builder().id(orgId).name("Acme Corp").slug("acme").build();

    rootLoginRule =
        DetectionRule.builder()
            .id(UUID.randomUUID())
            .name("AWS Root Account Console Login Without MFA")
            .description("Root console login without MFA")
            .ruleType(RuleType.SIGMA)
            .severity(AlertSeverity.CRITICAL)
            .cloudProvider(CloudProvider.AWS)
            .queryPattern("eventName:ConsoleLogin AND userIdentity.type:Root")
            .mitreAttackId("T1078.004")
            .riskScore(95)
            .isEnabled(true)
            .build();
  }

  @Test
  @DisplayName("ingest generates alert when telemetry event matches rule query pattern")
  void ingest_matchesRule_generatesAlert() {
    when(organizationRepository.findById(orgId)).thenReturn(Optional.of(testOrg));
    when(detectionRuleRepository.findByIsEnabledTrue()).thenReturn(List.of(rootLoginRule));

    UUID alertId = UUID.randomUUID();
    when(alertRepository.save(any(Alert.class)))
        .thenAnswer(
            invocation -> {
              Alert a = invocation.getArgument(0);
              a.setId(alertId);
              return a;
            });

    UUID eventId = UUID.randomUUID();
    when(telemetryEventRepository.save(any(TelemetryEvent.class)))
        .thenAnswer(
            invocation -> {
              TelemetryEvent e = invocation.getArgument(0);
              e.setId(eventId);
              return e;
            });

    TelemetryIngestRequest request =
        new TelemetryIngestRequest(
            "evt-12345",
            "aws.cloudtrail",
            "ConsoleLogin",
            "arn:aws:iam::123456789012:root",
            "198.51.100.23",
            "arn:aws:iam::123456789012:root",
            "aws",
            Map.of("MFAUsed", "No"));

    TelemetryIngestResponse response = ingestionService.ingest(request, orgId, null);

    assertThat(response.matched()).isTrue();
    assertThat(response.alertId()).isEqualTo(alertId);
    assertThat(response.telemetryId()).isEqualTo(eventId);
    verify(alertRepository).save(any(Alert.class));
    verify(telemetryEventRepository).save(any(TelemetryEvent.class));
  }

  @Test
  @DisplayName("ingest saves telemetry event without alert when no rule matches")
  void ingest_noMatch_doesNotGenerateAlert() {
    when(organizationRepository.findById(orgId)).thenReturn(Optional.of(testOrg));
    when(detectionRuleRepository.findByIsEnabledTrue()).thenReturn(List.of(rootLoginRule));

    UUID eventId = UUID.randomUUID();
    when(telemetryEventRepository.save(any(TelemetryEvent.class)))
        .thenAnswer(
            invocation -> {
              TelemetryEvent e = invocation.getArgument(0);
              e.setId(eventId);
              return e;
            });

    TelemetryIngestRequest request =
        new TelemetryIngestRequest(
            "evt-99999",
            "aws.cloudtrail",
            "DescribeInstances",
            "arn:aws:iam::123456789012:user/dev",
            "192.168.1.10",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
            "aws",
            Map.of("region", "us-east-1"));

    TelemetryIngestResponse response = ingestionService.ingest(request, orgId, null);

    assertThat(response.matched()).isFalse();
    assertThat(response.alertId()).isNull();
    assertThat(response.telemetryId()).isEqualTo(eventId);
    verify(telemetryEventRepository).save(any(TelemetryEvent.class));
  }
}
