package com.aegis.investigation.application.service;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.investigation.domain.entity.EvidenceArtifact;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.domain.entity.TimelineEvent;
import com.aegis.investigation.domain.model.ArtifactType;
import com.aegis.investigation.domain.model.IncidentStatus;
import com.aegis.investigation.domain.model.TimelineEventType;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentCorrelationEngine {

  private final IncidentJpaRepository incidentRepository;
  private static final int CORRELATION_WINDOW_MINUTES = 30;

  @Transactional
  public Incident correlateAlert(Alert alert) {
    UUID orgId = alert.getOrganization().getId();
    String targetResource = alert.getResourceId();
    Instant windowStart = Instant.now().minus(CORRELATION_WINDOW_MINUTES, ChronoUnit.MINUTES);

    List<IncidentStatus> activeStatuses =
        List.of(
            IncidentStatus.NEW,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ESCALATED,
            IncidentStatus.REMEDIATION_PENDING);

    // Search active incidents for existing matches on resource or provider
    Optional<Incident> existingIncident =
        incidentRepository.findAll().stream()
            .filter(i -> i.getOrganization().getId().equals(orgId))
            .filter(i -> activeStatuses.contains(i.getStatus()))
            .filter(i -> i.getCreatedAt().isAfter(windowStart))
            .filter(i -> matchesIncidentScope(i, alert))
            .findFirst();

    if (existingIncident.isPresent()) {
      Incident incident = existingIncident.get();
      log.info(
          "Correlating alert [{}] into existing active incident [{}] (Title: {})",
          alert.getId(),
          incident.getId(),
          incident.getTitle());

      incident.getAlerts().add(alert);

      // Boost risk score dynamically
      int currentRisk = incident.getRiskScore() != null ? incident.getRiskScore() : 50;
      int alertRisk = alert.getRiskScore() != null ? alert.getRiskScore() : 50;
      int escalatedRisk = Math.min(100, Math.max(currentRisk, alertRisk) + 10);
      incident.setRiskScore(escalatedRisk);

      // Elevate severity if incoming alert is higher
      if (alert.getSeverity() == AlertSeverity.CRITICAL) {
        incident.setSeverity(AlertSeverity.CRITICAL);
      } else if (alert.getSeverity() == AlertSeverity.HIGH
          && incident.getSeverity() != AlertSeverity.CRITICAL) {
        incident.setSeverity(AlertSeverity.HIGH);
      }

      // Add timeline event
      TimelineEvent timelineEvent =
          TimelineEvent.builder()
              .incident(incident)
              .eventType(TimelineEventType.ALERT_TRIGGERED)
              .title("Correlated Alert: " + alert.getTitle())
              .description(
                  "Correlated detection on resource ["
                      + alert.getResourceId()
                      + "] from rule ["
                      + (alert.getRule() != null ? alert.getRule().getName() : "Sigma Detection")
                      + "]. "
                      + alert.getDescription())
              .source(alert.getResourceType() + " (" + alert.getResourceId() + ")")
              .build();
      incident.getTimelineEvents().add(timelineEvent);

      // Add evidence artifact
      EvidenceArtifact artifact =
          EvidenceArtifact.builder()
              .incident(incident)
              .name("Alert Telemetry Artifact #" + alert.getId())
              .artifactType(ArtifactType.LOG_RECORD)
              .contentType("application/json")
              .checksum(sha256Hex(alert.getDescription()))
              .storageUri("s3://evidence/" + incident.getId() + "/alert-" + alert.getId() + ".json")
              .rawData(alert.getDescription())
              .build();
      incident.getEvidenceArtifacts().add(artifact);

      return incidentRepository.save(incident);
    }

    // Otherwise create brand new incident
    log.info(
        "Creating new incident for alert [{}] on resource [{}]", alert.getId(), targetResource);
    Incident newIncident =
        Incident.builder()
            .organization(alert.getOrganization())
            .workspace(alert.getWorkspace())
            .title("Security Incident: " + alert.getTitle())
            .summary(
                "Aggregated security incident involving resource ["
                    + targetResource
                    + "] detected by Sentinel Core engine.")
            .severity(alert.getSeverity())
            .status(IncidentStatus.NEW)
            .riskScore(alert.getRiskScore())
            .cloudProvider(alert.getCloudProvider())
            .alerts(new HashSet<>())
            .build();

    newIncident.getAlerts().add(alert);

    TimelineEvent alertTriggered =
        TimelineEvent.builder()
            .incident(newIncident)
            .eventType(TimelineEventType.ALERT_TRIGGERED)
            .title(alert.getTitle())
            .description(alert.getDescription())
            .source(alert.getResourceType() + " (" + targetResource + ")")
            .build();

    EvidenceArtifact artifact =
        EvidenceArtifact.builder()
            .incident(newIncident)
            .name("Alert Telemetry Artifact #" + alert.getId())
            .artifactType(ArtifactType.LOG_RECORD)
            .contentType("application/json")
            .checksum(sha256Hex(alert.getDescription()))
            .storageUri("s3://evidence/incoming/alert-" + alert.getId() + ".json")
            .rawData(alert.getDescription())
            .build();

    newIncident.getTimelineEvents().add(alertTriggered);
    newIncident.getEvidenceArtifacts().add(artifact);

    return incidentRepository.save(newIncident);
  }

  private boolean matchesIncidentScope(Incident incident, Alert alert) {
    if (incident.getAlerts().stream()
        .anyMatch(a -> a.getResourceId().equalsIgnoreCase(alert.getResourceId()))) {
      return true;
    }
    return incident.getCloudProvider() == alert.getCloudProvider()
        && (alert.getResourceId().contains(incident.getTitle())
            || incident.getSummary().contains(alert.getResourceId()));
  }

  private String sha256Hex(String data) {
    if (data == null) {
      return "0000000000000000000000000000000000000000000000000000000000000000";
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (Exception e) {
      return "hash_error";
    }
  }
}
