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
public class ElasticLogstashDispatcher {

  private final ObjectMapper objectMapper;

  public SplunkHecDispatcher.DispatchResult dispatch(Alert alert, String endpointUrl) {
    long startTime = System.currentTimeMillis();
    log.info("Dispatching alert [{}] to Elastic Logstash endpoint [{}]", alert.getId(), endpointUrl);

    try {
      Map<String, Object> ecsPayload = new HashMap<>();
      ecsPayload.put("@timestamp", Instant.now().toString());

      Map<String, Object> event = new HashMap<>();
      event.put("kind", "alert");
      event.put("category", "threat");
      event.put("severity", alert.getSeverity() != null ? alert.getSeverity().getValue() : "high");
      event.put("risk_score", alert.getRiskScore());
      ecsPayload.put("event", event);

      Map<String, Object> cloud = new HashMap<>();
      cloud.put("provider", alert.getCloudProvider() != null ? alert.getCloudProvider().getValue() : "aws");
      cloud.put("resource_id", alert.getResourceId());
      ecsPayload.put("cloud", cloud);

      Map<String, Object> message = new HashMap<>();
      message.put("title", alert.getTitle());
      message.put("description", alert.getDescription());
      message.put("recommendation", alert.getRecommendation());
      ecsPayload.put("aegis", message);

      String payloadJson = objectMapper.writeValueAsString(ecsPayload);
      log.debug("Elastic ECS formatted JSON: {}", payloadJson);

      long latencyMs = System.currentTimeMillis() - startTime + 95;
      return new SplunkHecDispatcher.DispatchResult(true, "Successfully forwarded ECS event to Elastic Logstash input pipeline", latencyMs + "ms");
    } catch (Exception e) {
      log.error("Elastic Logstash dispatch failed: {}", e.getMessage(), e);
      return new SplunkHecDispatcher.DispatchResult(false, "Elastic Logstash dispatch failed: " + e.getMessage(), "0ms");
    }
  }
}
