package com.aegis.detection.application.parser;

import com.aegis.detection.api.dto.TelemetryIngestRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AzureActivityLogParser {

  private final ObjectMapper objectMapper;

  public List<TelemetryIngestRequest> parse(Map<String, Object> payload) {
    if (payload == null || payload.isEmpty()) {
      return Collections.emptyList();
    }

    List<TelemetryIngestRequest> requests = new ArrayList<>();

    try {
      JsonNode root = objectMapper.valueToTree(payload);
      JsonNode records = root.has("records") ? root.get("records") : null;

      if (records != null && records.isArray()) {
        for (JsonNode record : records) {
          TelemetryIngestRequest req = parseSingleRecord(record);
          if (req != null) {
            requests.add(req);
          }
        }
      } else {
        TelemetryIngestRequest req = parseSingleRecord(root);
        if (req != null) {
          requests.add(req);
        }
      }
    } catch (Exception e) {
      log.error("Failed to parse Azure Activity Log payload: {}", e.getMessage(), e);
    }

    return requests;
  }

  private TelemetryIngestRequest parseSingleRecord(JsonNode node) {
    String operationName = node.path("operationName").asText(node.path("operation").asText(null));
    if (operationName == null || operationName.trim().isEmpty()) {
      return null;
    }

    String resourceId = node.path("resourceId").asText(null);
    String caller = node.path("caller").asText(node.path("claims").path("name").asText("unknown-principal"));
    String clientIp = node.path("httpRequest").path("clientIpAddress").asText(node.path("callerIp").asText(null));
    String correlationId = node.path("correlationId").asText(UUID.randomUUID().toString());

    String eventSource = "Microsoft.Azure";
    if (resourceId != null && resourceId.contains("/providers/")) {
      int idx = resourceId.indexOf("/providers/");
      int nextSlash = resourceId.indexOf('/', idx + 11);
      eventSource = nextSlash > 0 ? resourceId.substring(idx + 11, nextSlash) : resourceId.substring(idx + 11);
    } else if (operationName.contains("/")) {
      eventSource = operationName.substring(0, operationName.indexOf('/'));
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> rawMap = objectMapper.convertValue(node, Map.class);

    return new TelemetryIngestRequest(
        correlationId,
        eventSource,
        operationName,
        caller,
        clientIp,
        resourceId != null ? resourceId : "/subscriptions/azure-default",
        "azure",
        rawMap
    );
  }
}
