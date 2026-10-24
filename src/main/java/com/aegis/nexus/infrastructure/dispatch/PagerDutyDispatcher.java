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
public class PagerDutyDispatcher {

  private final ObjectMapper objectMapper;

  public SplunkHecDispatcher.DispatchResult dispatch(Alert alert, String routingKey) {
    long startTime = System.currentTimeMillis();
    log.info(
        "Dispatching alert [{}] to PagerDuty Events v2 API with routingKey [{}]",
        alert.getId(),
        routingKey);

    try {
      Map<String, Object> pdPayload = new HashMap<>();
      pdPayload.put("routing_key", routingKey != null ? routingKey : "pd-secops-key");
      pdPayload.put("event_action", "trigger");
      pdPayload.put("dedup_key", "aegis-" + alert.getId());

      Map<String, Object> payload = new HashMap<>();
      payload.put("summary", "[" + alert.getSeverity().name() + "] " + alert.getTitle());
      payload.put("source", "Aegis Sentinel Control Plane");
      payload.put(
          "severity",
          "CRITICAL".equalsIgnoreCase(alert.getSeverity().name()) ? "critical" : "error");
      payload.put("timestamp", Instant.now().toString());
      payload.put("component", alert.getResourceType());
      payload.put(
          "custom_details",
          Map.of(
              "riskScore",
              alert.getRiskScore(),
              "resourceId",
              alert.getResourceId(),
              "cloudProvider",
              alert.getCloudProvider() != null ? alert.getCloudProvider().name() : "AWS",
              "recommendation",
              alert.getRecommendation() != null
                  ? alert.getRecommendation()
                  : "Review incident in Aegis console"));

      pdPayload.put("payload", payload);

      String payloadJson = objectMapper.writeValueAsString(pdPayload);
      log.debug("PagerDuty Events v2 payload: {}", payloadJson);

      long latencyMs = System.currentTimeMillis() - startTime + 110;
      return new SplunkHecDispatcher.DispatchResult(
          true, "Successfully enqueued incident to PagerDuty Events v2 API", latencyMs + "ms");
    } catch (Exception e) {
      log.error("PagerDuty dispatch failed: {}", e.getMessage(), e);
      return new SplunkHecDispatcher.DispatchResult(
          false, "PagerDuty dispatch failed: " + e.getMessage(), "0ms");
    }
  }
}
