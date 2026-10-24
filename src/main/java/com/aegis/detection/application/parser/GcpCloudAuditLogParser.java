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
public class GcpCloudAuditLogParser {

  private final ObjectMapper objectMapper;

  public List<TelemetryIngestRequest> parse(Map<String, Object> payload) {
    if (payload == null || payload.isEmpty()) {
      return Collections.emptyList();
    }

    List<TelemetryIngestRequest> requests = new ArrayList<>();

    try {
      JsonNode root = objectMapper.valueToTree(payload);
      JsonNode entries = root.has("entries") ? root.get("entries") : null;

      if (entries != null && entries.isArray()) {
        for (JsonNode entry : entries) {
          TelemetryIngestRequest req = parseSingleLog(entry);
          if (req != null) {
            requests.add(req);
          }
        }
      } else {
        TelemetryIngestRequest req = parseSingleLog(root);
        if (req != null) {
          requests.add(req);
        }
      }
    } catch (Exception e) {
      log.error("Failed to parse GCP Cloud Audit Log payload: {}", e.getMessage(), e);
    }

    return requests;
  }

  private TelemetryIngestRequest parseSingleLog(JsonNode node) {
    JsonNode protoPayload = node.path("protoPayload");
    String methodName = protoPayload.path("methodName").asText(null);
    if (methodName == null || methodName.trim().isEmpty()) {
      methodName = node.path("methodName").asText(null);
      if (methodName == null) {
        return null;
      }
    }

    String serviceName =
        protoPayload.path("serviceName").asText(node.path("serviceName").asText("gcp.services"));
    String resourceName =
        protoPayload
            .path("resourceName")
            .asText(node.path("resourceName").asText("projects/_/global"));
    String principalEmail =
        protoPayload
            .path("authenticationInfo")
            .path("principalEmail")
            .asText(node.path("principal").asText("unknown-principal"));
    String callerIp =
        protoPayload
            .path("requestMetadata")
            .path("callerIp")
            .asText(node.path("callerIp").asText(null));
    String insertId = node.path("insertId").asText(UUID.randomUUID().toString());

    @SuppressWarnings("unchecked")
    Map<String, Object> rawMap = objectMapper.convertValue(node, Map.class);

    return new TelemetryIngestRequest(
        insertId, serviceName, methodName, principalEmail, callerIp, resourceName, "gcp", rawMap);
  }
}
