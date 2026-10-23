package com.aegis.investigation.application.service;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.investigation.api.dto.IncidentCommentResponse;
import com.aegis.investigation.api.dto.IncidentDetailResponse;
import com.aegis.investigation.api.dto.IncidentResponse;
import com.aegis.investigation.domain.entity.EvidenceArtifact;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.domain.entity.IncidentComment;
import com.aegis.investigation.domain.entity.TimelineEvent;
import com.aegis.investigation.domain.model.ArtifactType;
import com.aegis.investigation.domain.model.IncidentStatus;
import com.aegis.investigation.domain.model.TimelineEventType;
import com.aegis.investigation.infrastructure.persistence.jpa.EvidenceArtifactJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentCommentJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentSpecification;
import com.aegis.investigation.infrastructure.persistence.jpa.TimelineEventJpaRepository;
import java.time.Instant;
import java.util.HashSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentService {

  private final IncidentJpaRepository incidentRepository;
  private final TimelineEventJpaRepository timelineEventRepository;
  private final EvidenceArtifactJpaRepository evidenceArtifactRepository;
  private final IncidentCommentJpaRepository commentRepository;

  @Transactional(readOnly = true)
  public Page<IncidentResponse> getIncidents(
      UUID organizationId,
      UUID workspaceId,
      IncidentStatus status,
      AlertSeverity severity,
      String search,
      Pageable pageable) {

    Specification<Incident> spec =
        IncidentSpecification.filter(organizationId, workspaceId, status, severity, search);

    return incidentRepository.findAll(spec, pageable).map(IncidentResponse::fromEntity);
  }

  @Transactional(readOnly = true)
  public IncidentDetailResponse getIncidentDetail(UUID incidentId, UUID organizationId) {
    Incident incident =
        incidentRepository
            .findById(incidentId)
            .filter(i -> i.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Incident not found with id: " + incidentId));

    return IncidentDetailResponse.fromEntity(incident);
  }

  @Transactional
  public IncidentResponse updateIncidentStatus(
      UUID incidentId, UUID organizationId, IncidentStatus newStatus, String reason, UUID userId) {
    Incident incident =
        incidentRepository
            .findById(incidentId)
            .filter(i -> i.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Incident not found with id: " + incidentId));

    IncidentStatus previousStatus = incident.getStatus();
    incident.setStatus(newStatus);

    if (newStatus == IncidentStatus.CLOSED || newStatus == IncidentStatus.RESOLVED) {
      incident.setClosedAt(Instant.now());
    }

    TimelineEvent statusChange =
        TimelineEvent.builder()
            .incident(incident)
            .eventType(TimelineEventType.STATUS_CHANGED)
            .title("Incident status changed to " + newStatus.getValue())
            .description(
                reason != null && !reason.trim().isEmpty()
                    ? reason
                    : "Transitioned from "
                        + previousStatus.getValue()
                        + " to "
                        + newStatus.getValue())
            .source("analyst-action")
            .build();

    incident.getTimelineEvents().add(statusChange);
    Incident saved = incidentRepository.save(incident);

    log.info(
        "Incident {} status updated from {} to {} by user {}",
        incidentId,
        previousStatus,
        newStatus,
        userId);

    return IncidentResponse.fromEntity(saved);
  }

  @Transactional
  public IncidentCommentResponse addComment(
      UUID incidentId, UUID organizationId, String message, UUID authorId, String authorName) {
    Incident incident =
        incidentRepository
            .findById(incidentId)
            .filter(i -> i.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Incident not found with id: " + incidentId));

    IncidentComment comment =
        IncidentComment.builder()
            .incident(incident)
            .authorId(authorId)
            .authorName(authorName != null ? authorName : "Security Analyst")
            .message(message)
            .build();

    IncidentComment savedComment = commentRepository.save(comment);

    TimelineEvent commentEvent =
        TimelineEvent.builder()
            .incident(incident)
            .eventType(TimelineEventType.ANALYST_NOTE)
            .title("Analyst Annotation Added")
            .description(message)
            .source(authorName != null ? authorName : "analyst")
            .build();

    timelineEventRepository.save(commentEvent);

    return IncidentCommentResponse.fromEntity(savedComment);
  }

  @Transactional
  public Incident correlateAlertIntoIncident(Alert alert) {
    // Group into an active incident or create a new case
    Incident incident =
        Incident.builder()
            .organization(alert.getOrganization())
            .workspace(alert.getWorkspace())
            .title("Security Incident: " + alert.getTitle())
            .summary(
                "Aggregated security incident involving resource ["
                    + alert.getResourceId()
                    + "] detected by Sentinel Core.")
            .severity(alert.getSeverity())
            .status(IncidentStatus.NEW)
            .riskScore(alert.getRiskScore())
            .cloudProvider(alert.getCloudProvider())
            .alerts(new HashSet<>())
            .build();

    incident.getAlerts().add(alert);

    TimelineEvent alertTriggered =
        TimelineEvent.builder()
            .incident(incident)
            .eventType(TimelineEventType.ALERT_TRIGGERED)
            .title(alert.getTitle())
            .description(alert.getDescription())
            .source(alert.getResourceType() + " (" + alert.getResourceId() + ")")
            .build();

    EvidenceArtifact artifact =
        EvidenceArtifact.builder()
            .incident(incident)
            .name("Alert Telemetry Artifact #" + alert.getId())
            .artifactType(ArtifactType.LOG_RECORD)
            .contentType("application/json")
            .rawData(alert.getDescription())
            .build();

    incident.getTimelineEvents().add(alertTriggered);
    incident.getEvidenceArtifacts().add(artifact);

    Incident saved = incidentRepository.save(incident);
    log.info("Correlated alert {} into incident {}", alert.getId(), saved.getId());
    return saved;
  }
}
