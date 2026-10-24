package com.aegis.investigation.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.domain.model.IncidentStatus;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IncidentCorrelationEngineTest {

  @Mock private IncidentJpaRepository incidentRepository;

  private IncidentCorrelationEngine correlationEngine;

  private UUID orgId;
  private Organization testOrg;

  @BeforeEach
  void setUp() {
    correlationEngine = new IncidentCorrelationEngine(incidentRepository);
    orgId = UUID.randomUUID();
    testOrg = Organization.builder().id(orgId).name("Acme Corp").slug("acme").build();
  }

  @Test
  @DisplayName("Creates brand new incident dossier when no existing active incident matches")
  void correlateAlert_createsNewIncident() {
    when(incidentRepository.findAll()).thenReturn(List.of());
    when(incidentRepository.save(any(Incident.class))).thenAnswer(i -> i.getArgument(0));

    Alert alert =
        Alert.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .title("AWS Root Account Console Login")
            .description("Root console login without MFA")
            .severity(AlertSeverity.CRITICAL)
            .riskScore(95)
            .cloudProvider(CloudProvider.AWS)
            .resourceType("AWS::IAM::User")
            .resourceId("arn:aws:iam::123456789012:root")
            .build();

    Incident result = correlationEngine.correlateAlert(alert);

    assertThat(result).isNotNull();
    assertThat(result.getTitle()).contains("AWS Root Account Console Login");
    assertThat(result.getStatus()).isEqualTo(IncidentStatus.NEW);
    assertThat(result.getSeverity()).isEqualTo(AlertSeverity.CRITICAL);
    assertThat(result.getRiskScore()).isEqualTo(95);
    assertThat(result.getTimelineEvents()).hasSize(1);
    assertThat(result.getEvidenceArtifacts()).hasSize(1);
    verify(incidentRepository).save(any(Incident.class));
  }

  @Test
  @DisplayName(
      "Clusters alert into existing active incident on same resource within correlation window")
  void correlateAlert_clustersIntoExistingIncident() {
    Incident existingIncident =
        Incident.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .title("Security Incident: S3 Bucket Policy Changed")
            .severity(AlertSeverity.HIGH)
            .status(IncidentStatus.INVESTIGATING)
            .riskScore(75)
            .cloudProvider(CloudProvider.AWS)
            .createdAt(Instant.now().minusSeconds(120))
            .alerts(new HashSet<>())
            .timelineEvents(new ArrayList<>())
            .evidenceArtifacts(new ArrayList<>())
            .build();

    Alert initialAlert =
        Alert.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .resourceId("arn:aws:s3:::prod-customer-data")
            .resourceType("AWS::S3::Bucket")
            .cloudProvider(CloudProvider.AWS)
            .build();
    existingIncident.getAlerts().add(initialAlert);

    when(incidentRepository.findAll()).thenReturn(List.of(existingIncident));
    when(incidentRepository.save(any(Incident.class))).thenAnswer(i -> i.getArgument(0));

    Alert secondAlert =
        Alert.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .title("S3 Bucket Made Public Exfiltration")
            .description("Bucket policy modified to permit public read by anonymous principal")
            .severity(AlertSeverity.CRITICAL)
            .riskScore(95)
            .cloudProvider(CloudProvider.AWS)
            .resourceType("AWS::S3::Bucket")
            .resourceId("arn:aws:s3:::prod-customer-data")
            .build();

    Incident correlated = correlationEngine.correlateAlert(secondAlert);

    assertThat(correlated.getId()).isEqualTo(existingIncident.getId());
    assertThat(correlated.getAlerts()).hasSize(2);
    assertThat(correlated.getSeverity()).isEqualTo(AlertSeverity.CRITICAL);
    assertThat(correlated.getRiskScore()).isGreaterThan(75);
    assertThat(correlated.getTimelineEvents()).hasSize(1);
    assertThat(correlated.getEvidenceArtifacts()).hasSize(1);
    verify(incidentRepository).save(existingIncident);
  }
}
