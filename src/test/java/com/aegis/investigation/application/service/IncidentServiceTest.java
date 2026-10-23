package com.aegis.investigation.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.investigation.api.dto.IncidentCommentResponse;
import com.aegis.investigation.api.dto.IncidentDetailResponse;
import com.aegis.investigation.api.dto.IncidentResponse;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.domain.entity.IncidentComment;
import com.aegis.investigation.domain.entity.TimelineEvent;
import com.aegis.investigation.domain.model.IncidentStatus;
import com.aegis.investigation.infrastructure.persistence.jpa.EvidenceArtifactJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentCommentJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.TimelineEventJpaRepository;
import com.aegis.investigation.infrastructure.storage.MinioEvidenceStorageService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IncidentServiceTest {

  @Mock private IncidentJpaRepository incidentRepository;
  @Mock private TimelineEventJpaRepository timelineEventRepository;
  @Mock private EvidenceArtifactJpaRepository evidenceArtifactRepository;
  @Mock private IncidentCommentJpaRepository commentRepository;
  @Mock private IncidentCorrelationEngine correlationEngine;
  @Mock private MinioEvidenceStorageService minioStorageService;

  private IncidentService incidentService;

  private UUID orgId;
  private UUID incidentId;
  private Organization testOrg;
  private Incident testIncident;

  @BeforeEach
  void setUp() {
    incidentService =
        new IncidentService(
            incidentRepository,
            timelineEventRepository,
            evidenceArtifactRepository,
            commentRepository,
            correlationEngine,
            minioStorageService);

    orgId = UUID.randomUUID();
    incidentId = UUID.randomUUID();
    testOrg = Organization.builder().id(orgId).name("Acme Corp").slug("acme").build();

    testIncident =
        Incident.builder()
            .id(incidentId)
            .organization(testOrg)
            .title("Security Incident: Root Account Console Login")
            .summary("Root login anomaly detected without MFA.")
            .severity(AlertSeverity.CRITICAL)
            .status(IncidentStatus.NEW)
            .riskScore(95)
            .cloudProvider(CloudProvider.AWS)
            .alerts(new HashSet<>())
            .timelineEvents(new ArrayList<>())
            .evidenceArtifacts(new ArrayList<>())
            .comments(new ArrayList<>())
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();
  }

  @Test
  @DisplayName("getIncidentDetail returns full dossier when incident belongs to org")
  void getIncidentDetail_success() {
    when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(testIncident));

    IncidentDetailResponse response = incidentService.getIncidentDetail(incidentId, orgId);

    assertThat(response).isNotNull();
    assertThat(response.id()).isEqualTo(incidentId);
    assertThat(response.title()).isEqualTo("Security Incident: Root Account Console Login");
    assertThat(response.status()).isEqualTo("new");
    assertThat(response.severity()).isEqualTo("critical");
  }

  @Test
  @DisplayName("updateIncidentStatus transitions state and records timeline event")
  void updateIncidentStatus_success() {
    when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(testIncident));
    when(incidentRepository.save(any(Incident.class))).thenAnswer(i -> i.getArgument(0));

    UUID userId = UUID.randomUUID();
    IncidentResponse response =
        incidentService.updateIncidentStatus(
            incidentId, orgId, IncidentStatus.INVESTIGATING, "Analyst assigned to review", userId);

    assertThat(response.status()).isEqualTo("investigating");
    assertThat(testIncident.getTimelineEvents()).hasSize(1);
    assertThat(testIncident.getTimelineEvents().get(0).getTitle())
        .isEqualTo("Incident status changed to investigating");
  }

  @Test
  @DisplayName("addComment saves comment and creates timeline entry")
  void addComment_success() {
    when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(testIncident));
    when(commentRepository.save(any(IncidentComment.class)))
        .thenAnswer(
            invocation -> {
              IncidentComment c = invocation.getArgument(0);
              c.setId(UUID.randomUUID());
              return c;
            });

    UUID authorId = UUID.randomUUID();
    IncidentCommentResponse response =
        incidentService.addComment(
            incidentId,
            orgId,
            "Verified IP is associated with known VPN node",
            authorId,
            "Jane Doe");

    assertThat(response.message()).isEqualTo("Verified IP is associated with known VPN node");
    assertThat(response.authorName()).isEqualTo("Jane Doe");
    verify(commentRepository).save(any(IncidentComment.class));
    verify(timelineEventRepository).save(any(TimelineEvent.class));
  }

  @Test
  @DisplayName("correlateAlertIntoIncident delegates to IncidentCorrelationEngine")
  void correlateAlertIntoIncident_success() {
    Alert alert =
        Alert.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .title("S3 Bucket Made Public")
            .description("Bucket policy modified to permit public read")
            .severity(AlertSeverity.CRITICAL)
            .riskScore(92)
            .cloudProvider(CloudProvider.AWS)
            .resourceType("AWS::S3::Bucket")
            .resourceId("arn:aws:s3:::prod-customer-data")
            .build();

    Incident expectedIncident =
        Incident.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .title("Security Incident: S3 Bucket Made Public")
            .severity(AlertSeverity.CRITICAL)
            .build();

    when(correlationEngine.correlateAlert(alert)).thenReturn(expectedIncident);

    Incident created = incidentService.correlateAlertIntoIncident(alert);

    assertThat(created).isNotNull();
    assertThat(created.getTitle()).contains("S3 Bucket Made Public");
    verify(correlationEngine).correlateAlert(alert);
  }
}
