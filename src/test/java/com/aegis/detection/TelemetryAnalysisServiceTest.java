package com.aegis.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.aegis.common.exception.BadRequestException;
import com.aegis.detection.api.dto.TelemetryAnalysisRequest;
import com.aegis.detection.api.dto.TelemetryAnalysisResponse;
import com.aegis.detection.application.service.TelemetryAnalysisService;
import com.aegis.detection.infrastructure.persistence.jpa.DetectionRuleJpaRepository;
import com.aegis.intelligence.infrastructure.ai.AiModelClient;
import com.aegis.intelligence.infrastructure.persistence.jpa.ThreatIndicatorJpaRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TelemetryAnalysisServiceTest {

  @Mock private AiModelClient aiModelClient;
  @Mock private ThreatIndicatorJpaRepository threatIndicatorRepository;
  @Mock private DetectionRuleJpaRepository detectionRuleRepository;

  private TelemetryAnalysisService telemetryAnalysisService;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @BeforeEach
  void setUp() {
    telemetryAnalysisService =
        new TelemetryAnalysisService(
            objectMapper, aiModelClient, threatIndicatorRepository, detectionRuleRepository);
  }

  @Test
  @DisplayName("Should detect and analyze valid AWS CloudTrail log")
  void shouldAnalyzeCloudTrailLog() {
    String cloudTrailJson =
        """
        {
          "eventVersion": "1.08",
          "userIdentity": { "type": "IAMUser", "principalId": "AIDAJ45WYROZEXAMPLE" },
          "eventTime": "2026-03-28T03:15:22Z",
          "eventSource": "s3.amazonaws.com",
          "eventName": "GetObject",
          "sourceIPAddress": "198.51.100.44",
          "userAgent": "aws-sdk-go/v1.44.180 TorBrowser/12.5"
        }
        """;

    TelemetryAnalysisRequest req = new TelemetryAnalysisRequest(cloudTrailJson, "4way");
    TelemetryAnalysisResponse response = telemetryAnalysisService.analyze(req);

    assertThat(response.formatDetected()).isEqualTo("AWS CloudTrail");
    assertThat(response.verdict()).isEqualTo("CRITICAL");
    assertThat(response.fusedAnomalyScore()).isGreaterThan(0.9);
    assertThat(response.modelsUsed()).isNotEmpty();
    assertThat(response.extractedEntities().sourceIp()).isEqualTo("198.51.100.44");
  }

  @Test
  @DisplayName("Should detect and analyze valid Linux Syslog format")
  void shouldAnalyzeLinuxSyslog() {
    String syslog =
        "Mar 28 03:14:18 edge-gateway-01 sshd[14820]: Failed password for invalid user admin from 203.0.113.195 port 51222 ssh2";

    TelemetryAnalysisRequest req = new TelemetryAnalysisRequest(syslog, "4way");
    TelemetryAnalysisResponse response = telemetryAnalysisService.analyze(req);

    assertThat(response.formatDetected()).isEqualTo("Linux Syslog / Auth");
    assertThat(response.verdict()).isEqualTo("HIGH");
    assertThat(response.extractedEntities().sourceIp()).isEqualTo("203.0.113.195");
  }

  @Test
  @DisplayName("Should reject malformed JSON with descriptive 400 error")
  void shouldRejectMalformedJson() {
    String brokenJson = "{ eventSource: 'broken_json', missing_quotes: }";
    TelemetryAnalysisRequest req = new TelemetryAnalysisRequest(brokenJson, "4way");

    assertThatThrownBy(() -> telemetryAnalysisService.analyze(req))
        .isInstanceOf(BadRequestException.class)
        .hasMessageContaining("Malformed log syntax");
  }

  @Test
  @DisplayName("Should reject arbitrary non-telemetry JSON with schema error")
  void shouldRejectArbitraryJson() {
    String randomJson = "{ \"customerName\": \"John Doe\", \"accountBalance\": 1200 }";
    TelemetryAnalysisRequest req = new TelemetryAnalysisRequest(randomJson, "4way");

    assertThatThrownBy(() -> telemetryAnalysisService.analyze(req))
        .isInstanceOf(BadRequestException.class)
        .hasMessageContaining("Unrecognized telemetry schema");
  }

  @Test
  @DisplayName("Should reject empty or whitespace-only log")
  void shouldRejectEmptyLog() {
    TelemetryAnalysisRequest req = new TelemetryAnalysisRequest("   ", "4way");

    assertThatThrownBy(() -> telemetryAnalysisService.analyze(req))
        .isInstanceOf(BadRequestException.class)
        .hasMessageContaining("Log content cannot be empty");
  }
}
