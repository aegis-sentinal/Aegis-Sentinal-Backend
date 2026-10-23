package com.aegis.detection.application.service;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.detection.api.dto.AlertResponse;
import com.aegis.detection.api.dto.DashboardMetricsResponse;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.detection.infrastructure.persistence.jpa.AlertSpecification;
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
public class AlertService {

  private final AlertJpaRepository alertRepository;

  @Transactional(readOnly = true)
  public Page<AlertResponse> getAlerts(
      UUID organizationId,
      UUID workspaceId,
      AlertSeverity severity,
      AlertStatus status,
      CloudProvider cloudProvider,
      String search,
      Pageable pageable) {

    Specification<Alert> spec =
        AlertSpecification.filter(
            organizationId, workspaceId, severity, status, cloudProvider, search);

    return alertRepository.findAll(spec, pageable).map(AlertResponse::fromEntity);
  }

  @Transactional(readOnly = true)
  public AlertResponse getAlertById(UUID id, UUID organizationId) {
    Alert alert =
        alertRepository
            .findById(id)
            .filter(a -> a.getOrganization().getId().equals(organizationId))
            .orElseThrow(() -> new ResourceNotFoundException("Alert not found with id: " + id));

    return AlertResponse.fromEntity(alert);
  }

  @Transactional
  public AlertResponse updateAlertStatus(
      UUID id, UUID organizationId, AlertStatus newStatus, String notes) {
    Alert alert =
        alertRepository
            .findById(id)
            .filter(a -> a.getOrganization().getId().equals(organizationId))
            .orElseThrow(() -> new ResourceNotFoundException("Alert not found with id: " + id));

    alert.setStatus(newStatus);
    if (notes != null && !notes.trim().isEmpty()) {
      alert.setResolutionNotes(notes);
    }

    Alert saved = alertRepository.save(alert);
    log.info("Alert {} status updated to {} for org {}", id, newStatus, organizationId);
    return AlertResponse.fromEntity(saved);
  }

  @Transactional(readOnly = true)
  public DashboardMetricsResponse getDashboardMetrics(UUID organizationId, UUID workspaceId) {
    long totalAlerts = alertRepository.countByOrganizationId(organizationId);
    long criticalAlerts =
        alertRepository.countByOrganizationIdAndSeverity(organizationId, AlertSeverity.CRITICAL);
    long openAlerts =
        alertRepository.countByOrganizationIdAndStatus(organizationId, AlertStatus.OPEN);
    long resolvedAlerts =
        alertRepository.countByOrganizationIdAndStatus(organizationId, AlertStatus.RESOLVED);

    String threatLevel = "normal";
    if (criticalAlerts > 5) {
      threatLevel = "critical";
    } else if (criticalAlerts > 0 || openAlerts > 10) {
      threatLevel = "elevated";
    }

    return new DashboardMetricsResponse(
        totalAlerts,
        criticalAlerts,
        openAlerts,
        resolvedAlerts,
        1800000L,
        30,
        threatLevel,
        totalAlerts > 0 ? (double) resolvedAlerts / totalAlerts * 100.0 : 0.0);
  }
}
