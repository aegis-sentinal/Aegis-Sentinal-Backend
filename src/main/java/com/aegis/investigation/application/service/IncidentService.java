package com.aegis.investigation.application.service;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.investigation.api.dto.EvidenceArtifactResponse;
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
import com.aegis.investigation.infrastructure.storage.MinioEvidenceStorageService;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
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
  private final IncidentCorrelationEngine correlationEngine;
  private final MinioEvidenceStorageService minioStorageService;

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
    return correlationEngine.correlateAlert(alert);
  }

  public record EvidenceDownload(
      String filename,
      String contentType,
      byte[] data
  ) {}

  @Transactional
  public EvidenceArtifactResponse uploadEvidence(
      UUID incidentId,
      UUID organizationId,
      String filename,
      String artifactTypeStr,
      String contentType,
      byte[] data,
      String authorName) {
    Incident incident =
        incidentRepository
            .findById(incidentId)
            .filter(i -> i.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Incident not found with id: " + incidentId));

    ArtifactType type = ArtifactType.LOG_RECORD;
    if (artifactTypeStr != null) {
      try {
        type = ArtifactType.valueOf(artifactTypeStr.toUpperCase());
      } catch (Exception ignored) {}
    }

    var uploadResult = minioStorageService.storeEvidence(incidentId, filename, contentType, data);

    String rawPreview = data != null && data.length < 50000
        ? new String(data, StandardCharsets.UTF_8)
        : "[Binary artifact stored in MinIO: " + uploadResult.storageUri() + "]";

    EvidenceArtifact artifact =
        EvidenceArtifact.builder()
            .incident(incident)
            .name(filename != null ? filename : "forensic-evidence.bin")
            .artifactType(type)
            .contentType(contentType != null ? contentType : "application/octet-stream")
            .checksum(uploadResult.checksum())
            .storageUri(uploadResult.storageUri())
            .rawData(rawPreview)
            .build();

    EvidenceArtifact savedArtifact = evidenceArtifactRepository.save(artifact);

    TimelineEvent event =
        TimelineEvent.builder()
            .incident(incident)
            .eventType(TimelineEventType.EVIDENCE_COLLECTED)
            .title("Forensic Evidence Uploaded: " + artifact.getName())
            .description("Artifact SHA-256: " + uploadResult.checksum() + " (" + (data != null ? data.length : 0) + " bytes)")
            .source(authorName != null ? authorName : "forensics")
            .build();
    timelineEventRepository.save(event);

    return EvidenceArtifactResponse.fromEntity(savedArtifact);
  }

  @Transactional(readOnly = true)
  public EvidenceDownload downloadEvidence(UUID incidentId, UUID evidenceId, UUID organizationId) {
    Incident incident =
        incidentRepository
            .findById(incidentId)
            .filter(i -> i.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Incident not found with id: " + incidentId));

    EvidenceArtifact artifact =
        evidenceArtifactRepository
            .findById(evidenceId)
            .filter(a -> a.getIncident().getId().equals(incident.getId()))
            .orElseThrow(
                () -> new ResourceNotFoundException("Evidence artifact not found: " + evidenceId));

    byte[] bytes = minioStorageService.retrieveEvidence(artifact.getStorageUri());
    return new EvidenceDownload(artifact.getName(), artifact.getContentType(), bytes);
  }

  @Transactional(readOnly = true)
  public List<com.aegis.investigation.api.dto.TimelineEventResponse> getAggregatedTimeline(
      UUID incidentId, UUID organizationId) {
    Incident incident =
        incidentRepository
            .findById(incidentId)
            .filter(i -> i.getOrganization().getId().equals(organizationId))
            .orElseThrow(
                () -> new ResourceNotFoundException("Incident not found with id: " + incidentId));

    return incident.getTimelineEvents() != null
        ? incident.getTimelineEvents().stream()
            .map(com.aegis.investigation.api.dto.TimelineEventResponse::fromEntity)
            .toList()
        : Collections.emptyList();
  }
}
