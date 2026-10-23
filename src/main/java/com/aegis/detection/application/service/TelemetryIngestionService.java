package com.aegis.detection.application.service;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.detection.api.dto.TelemetryIngestRequest;
import com.aegis.detection.api.dto.TelemetryIngestResponse;
import com.aegis.detection.application.parser.AzureActivityLogParser;
import com.aegis.detection.application.parser.GcpCloudAuditLogParser;
import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.entity.DetectionRule;
import com.aegis.detection.domain.entity.TelemetryEvent;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.AlertStatus;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.detection.infrastructure.persistence.jpa.DetectionRuleJpaRepository;
import com.aegis.detection.infrastructure.persistence.jpa.TelemetryEventJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.Workspace;
import com.aegis.identity.infrastructure.persistence.jpa.OrganizationJpaRepository;
import com.aegis.identity.infrastructure.persistence.jpa.WorkspaceJpaRepository;
import com.aegis.intelligence.domain.entity.ThreatIndicator;
import com.aegis.intelligence.infrastructure.persistence.jpa.ThreatIndicatorJpaRepository;
import com.aegis.nexus.application.service.SiemForwardingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class TelemetryIngestionService {

  private final TelemetryEventJpaRepository telemetryEventRepository;
  private final DetectionRuleJpaRepository detectionRuleRepository;
  private final AlertJpaRepository alertRepository;
  private final OrganizationJpaRepository organizationRepository;
  private final WorkspaceJpaRepository workspaceRepository;
  private final ObjectMapper objectMapper;
  private final com.aegis.investigation.application.service.IncidentService incidentService;
  private final AzureActivityLogParser azureParser;
  private final GcpCloudAuditLogParser gcpParser;
  private final ThreatIndicatorJpaRepository threatIndicatorRepository;
  private final SiemForwardingService siemForwardingService;

  @Transactional
  public TelemetryIngestResponse ingest(
      TelemetryIngestRequest request, UUID organizationId, UUID workspaceId) {
    Organization org =
        organizationRepository
            .findById(organizationId)
            .orElseThrow(
                () ->
                    new ResourceNotFoundException(
                        "Organization not found with id: " + organizationId));

    Workspace ws = null;
    if (workspaceId != null) {
      ws = workspaceRepository.findById(workspaceId).orElse(null);
    }

    String rawPayloadJson = null;
    if (request.rawPayload() != null) {
      try {
        rawPayloadJson = objectMapper.writeValueAsString(request.rawPayload());
      } catch (Exception e) {
        log.warn("Failed to serialize raw telemetry payload: {}", e.getMessage());
      }
    }

    CloudProvider cloudProvider =
        request.cloudProvider() != null
            ? CloudProvider.fromValue(request.cloudProvider())
            : CloudProvider.AWS;

    TelemetryEvent event =
        TelemetryEvent.builder()
            .organization(org)
            .workspace(ws)
            .eventId(request.eventId())
            .eventSource(request.eventSource())
            .eventName(request.eventName())
            .principalId(request.principalId())
            .sourceIp(request.sourceIp())
            .destinationResource(request.destinationResource())
            .cloudProvider(cloudProvider)
            .rawPayload(rawPayloadJson)
            .processed(false)
            .build();

    // Check Watchtower Threat Intelligence feeds for IoC matches
    ThreatIndicator matchedIoC = null;
    if (request.sourceIp() != null) {
      matchedIoC =
          threatIndicatorRepository.findByIndicatorIgnoreCase(request.sourceIp()).orElse(null);
    }
    if (matchedIoC == null && request.principalId() != null) {
      matchedIoC =
          threatIndicatorRepository.findByIndicatorIgnoreCase(request.principalId()).orElse(null);
    }

    // Evaluate against active detection rules
    List<DetectionRule> activeRules = detectionRuleRepository.findByIsEnabledTrue();
    DetectionRule matchedRule = null;

    for (DetectionRule rule : activeRules) {
      if (matches(rule, request, cloudProvider)) {
        matchedRule = rule;
        break;
      }
    }

    UUID alertId = null;
    if (matchedRule != null || matchedIoC != null) {
      event.setProcessed(true);
      event.setMatchedRule(matchedRule);

      String resourceTarget =
          request.destinationResource() != null
              ? request.destinationResource()
              : (request.principalId() != null
                  ? request.principalId()
                  : "cloud:" + cloudProvider.getValue().toLowerCase() + ":telemetry");

      String title;
      String description;
      AlertSeverity severity;
      int riskScore;

      if (matchedRule != null) {
        title = matchedRule.getName();
        description =
            matchedRule.getDescription()
                + " (Observed: "
                + request.eventName()
                + " from "
                + (request.sourceIp() != null ? request.sourceIp() : "unknown IP")
                + ")";
        severity = matchedRule.getSeverity();
        riskScore = matchedRule.getRiskScore();
      } else {
        title = "Watchtower Threat Intel Hit: " + matchedIoC.getType();
        description =
            "Observed activity from recognized adversary indicator: "
                + matchedIoC.getIndicator()
                + ". "
                + matchedIoC.getThreatDescription();
        severity = AlertSeverity.HIGH;
        riskScore = matchedIoC.getConfidenceScore();
      }

      if (matchedIoC != null) {
        severity = AlertSeverity.CRITICAL;
        riskScore = Math.max(riskScore, 95);
        description +=
            " [CRITICAL WATCHTOWER MATCH: "
                + matchedIoC.getIndicator()
                + " ("
                + matchedIoC.getThreatDescription()
                + ")]";
      }

      Alert alert =
          Alert.builder()
              .organization(org)
              .workspace(ws)
              .rule(matchedRule)
              .title(title)
              .description(description)
              .severity(severity)
              .status(AlertStatus.OPEN)
              .riskScore(riskScore)
              .cloudProvider(cloudProvider)
              .resourceType(request.eventSource())
              .resourceId(resourceTarget)
              .affectedServices(request.eventSource() + ", Sentinel Core")
              .recommendation(
                  "Review identity and access activity for "
                      + (request.principalId() != null ? request.principalId() : "the actor")
                      + ". Initiate Forge containment workflow if unauthorized.")
              .build();

      Alert savedAlert = alertRepository.save(alert);
      alertId = savedAlert.getId();

      try {
        incidentService.correlateAlertIntoIncident(savedAlert);
      } catch (Exception e) {
        log.warn(
            "Failed to correlate alert {} into incident: {}", savedAlert.getId(), e.getMessage());
      }

      try {
        siemForwardingService.dispatchAlertToConnectedSiems(savedAlert);
      } catch (Exception e) {
        log.warn(
            "Failed forwarding alert {} to connected SIEMs: {}",
            savedAlert.getId(),
            e.getMessage());
      }

      log.warn(
          "🚨 SECURITY ALERT GENERATED [{}]: {} for org {}",
          savedAlert.getId(),
          savedAlert.getTitle(),
          org.getId());
    }

    TelemetryEvent savedEvent = telemetryEventRepository.save(event);

    return new TelemetryIngestResponse(
        savedEvent.getId(),
        matchedRule != null || matchedIoC != null,
        alertId,
        (matchedRule != null || matchedIoC != null)
            ? "Telemetry matched detection/intel rules; alert generated."
            : "Telemetry ingested and processed successfully; no rule matched.");
  }

  @Transactional
  public List<TelemetryIngestResponse> ingestAzure(
      Map<String, Object> payload, UUID organizationId, UUID workspaceId) {
    List<TelemetryIngestRequest> requests = azureParser.parse(payload);
    List<TelemetryIngestResponse> responses = new ArrayList<>();
    for (TelemetryIngestRequest req : requests) {
      responses.add(ingest(req, organizationId, workspaceId));
    }
    return responses;
  }

  @Transactional
  public List<TelemetryIngestResponse> ingestGcp(
      Map<String, Object> payload, UUID organizationId, UUID workspaceId) {
    List<TelemetryIngestRequest> requests = gcpParser.parse(payload);
    List<TelemetryIngestResponse> responses = new ArrayList<>();
    for (TelemetryIngestRequest req : requests) {
      responses.add(ingest(req, organizationId, workspaceId));
    }
    return responses;
  }

  private boolean matches(
      DetectionRule rule, TelemetryIngestRequest request, CloudProvider incomingProvider) {
    if (rule.getCloudProvider() != null && incomingProvider != null) {
      if (rule.getCloudProvider() != incomingProvider) {
        return false;
      }
    }

    String pattern = rule.getQueryPattern();
    if (pattern == null || request.eventName() == null) {
      return false;
    }

    String target = request.eventName().toLowerCase();
    String patternLower = pattern.toLowerCase();

    return patternLower.contains("eventname:" + target)
        || patternLower.contains(target)
        || (request.eventSource() != null
            && patternLower.contains(request.eventSource().toLowerCase()));
  }
}
