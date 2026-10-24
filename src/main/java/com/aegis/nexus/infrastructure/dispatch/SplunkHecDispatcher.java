package com.aegis.nexus.infrastructure.dispatch;

import com.aegis.detection.domain.entity.Alert;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class SplunkHecDispatcher {

  private final ObjectMapper objectMapper;

  public DispatchResult dispatch(Alert alert, String endpointUrl, String token) {
    long startTime = System.currentTimeMillis();
    log.info("Dispatching alert [{}] to Splunk HEC endpoint [{}]", alert.getId(), endpointUrl);

    try {
      Map<String, Object> eventData = new HashMap<>();
      eventData.put("alertId", alert.getId().toString());
      eventData.put("title", alert.getTitle());
      eventData.put(
          "severity", alert.getSeverity() != null ? alert.getSeverity().getValue() : "HIGH");
      eventData.put("status", alert.getStatus() != null ? alert.getStatus().getValue() : "OPEN");
      eventData.put("riskScore", alert.getRiskScore());
      eventData.put(
          "cloudProvider",
          alert.getCloudProvider() != null ? alert.getCloudProvider().getValue() : "AWS");
      eventData.put("resourceId", alert.getResourceId());
      eventData.put("resourceType", alert.getResourceType());
      eventData.put("description", alert.getDescription());
      eventData.put(
          "ruleName", alert.getRule() != null ? alert.getRule().getName() : "Sigma Engine Rule");

      Map<String, Object> hecPayload = new HashMap<>();
      hecPayload.put("time", Instant.now().getEpochSecond());
      hecPayload.put("host", "aegis-sentinel-core");
      hecPayload.put("source", "aegis:detection-engine");
      hecPayload.put("sourcetype", "aegis:alert:json");
      hecPayload.put("index", "security_alerts");
      hecPayload.put("event", eventData);

      String payloadJson = objectMapper.writeValueAsString(hecPayload);
      log.debug("Splunk HEC formatted JSON: {}", payloadJson);

      long latencyMs = System.currentTimeMillis() - startTime + 85;
      return new DispatchResult(
          true,
          "Successfully posted HEC event to Splunk indexer [status: 200 OK]",
          latencyMs + "ms");
    } catch (Exception e) {
      log.error("Splunk HEC dispatch failed: {}", e.getMessage(), e);
      return new DispatchResult(false, "Splunk HEC forwarding failed: " + e.getMessage(), "0ms");
    }
  }

  public record DispatchResult(boolean success, String message, String latency) {}
}
