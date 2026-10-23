package com.aegis.detection.application.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.aegis.detection.api.dto.TelemetryIngestRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MultiCloudParserTest {

  private AzureActivityLogParser azureParser;
  private GcpCloudAuditLogParser gcpParser;
  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
    azureParser = new AzureActivityLogParser(objectMapper);
    gcpParser = new GcpCloudAuditLogParser(objectMapper);
  }

  @Test
  @DisplayName("Azure parser extracts normalized telemetry requests from Activity Log records")
  void azureParser_parsesValidPayload() {
    Map<String, Object> record =
        Map.of(
            "operationName", "Microsoft.Authorization/roleAssignments/write",
            "resourceId", "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Authorization/roleAssignments/ra-1",
            "caller", "admin@company.com",
            "httpRequest", Map.of("clientIpAddress", "198.51.100.22"),
            "correlationId", "corr-12345");

    Map<String, Object> payload = Map.of("records", List.of(record));

    List<TelemetryIngestRequest> requests = azureParser.parse(payload);

    assertThat(requests).hasSize(1);
    TelemetryIngestRequest req = requests.get(0);
    assertThat(req.eventName()).isEqualTo("Microsoft.Authorization/roleAssignments/write");
    assertThat(req.cloudProvider()).isEqualTo("azure");
    assertThat(req.principalId()).isEqualTo("admin@company.com");
    assertThat(req.sourceIp()).isEqualTo("198.51.100.22");
    assertThat(req.destinationResource()).contains("Microsoft.Authorization/roleAssignments/ra-1");
  }

  @Test
  @DisplayName("GCP parser extracts normalized telemetry requests from Cloud Audit Log entries")
  void gcpParser_parsesValidPayload() {
    Map<String, Object> entry =
        Map.of(
            "insertId", "insert-gcp-99",
            "protoPayload",
                Map.of(
                    "serviceName", "storage.googleapis.com",
                    "methodName", "storage.setIamPermissions",
                    "resourceName", "projects/_/buckets/acme-confidential-data",
                    "authenticationInfo", Map.of("principalEmail", "service-account@acme-prod.iam.gserviceaccount.com"),
                    "requestMetadata", Map.of("callerIp", "203.0.113.88")));

    Map<String, Object> payload = Map.of("entries", List.of(entry));

    List<TelemetryIngestRequest> requests = gcpParser.parse(payload);

    assertThat(requests).hasSize(1);
    TelemetryIngestRequest req = requests.get(0);
    assertThat(req.eventName()).isEqualTo("storage.setIamPermissions");
    assertThat(req.cloudProvider()).isEqualTo("gcp");
    assertThat(req.principalId()).isEqualTo("service-account@acme-prod.iam.gserviceaccount.com");
    assertThat(req.sourceIp()).isEqualTo("203.0.113.88");
    assertThat(req.destinationResource()).isEqualTo("projects/_/buckets/acme-confidential-data");
  }
}
