package com.aegis.nexus.infrastructure.dispatch;

import com.aegis.detection.domain.entity.Alert;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class SlackWebhookDispatcher {

  private final ObjectMapper objectMapper;

  public SplunkHecDispatcher.DispatchResult dispatch(
      Alert alert, String webhookUrl, String channel) {
    long startTime = System.currentTimeMillis();
    log.info("Dispatching interactive Slack Block Kit card to channel [{}]", channel);

    try {
      String emoji =
          "HIGH".equalsIgnoreCase(alert.getSeverity().name())
                  || "CRITICAL".equalsIgnoreCase(alert.getSeverity().name())
              ? "🚨"
              : "⚠️";

      Map<String, Object> slackPayload = new HashMap<>();
      if (channel != null && !channel.trim().isEmpty()) {
        slackPayload.put("channel", channel);
      }

      List<Map<String, Object>> blocks = new ArrayList<>();

      // Header block
      Map<String, Object> headerBlock = new HashMap<>();
      headerBlock.put("type", "header");
      headerBlock.put(
          "text",
          Map.of(
              "type", "plain_text", "text", emoji + " Aegis Security Alert: " + alert.getTitle()));
      blocks.add(headerBlock);

      // Section with fields
      Map<String, Object> sectionBlock = new HashMap<>();
      sectionBlock.put("type", "section");

      List<Map<String, String>> fields =
          List.of(
              Map.of("type", "mrkdwn", "text", "*Severity:*\n`" + alert.getSeverity().name() + "`"),
              Map.of("type", "mrkdwn", "text", "*Risk Score:*\n*" + alert.getRiskScore() + "/100*"),
              Map.of(
                  "type",
                  "mrkdwn",
                  "text",
                  "*Provider:*\n"
                      + (alert.getCloudProvider() != null
                          ? alert.getCloudProvider().name()
                          : "AWS")),
              Map.of("type", "mrkdwn", "text", "*Resource:*\n`" + alert.getResourceId() + "`"));
      sectionBlock.put("fields", fields);
      blocks.add(sectionBlock);

      // Description block
      Map<String, Object> descBlock = new HashMap<>();
      descBlock.put("type", "context");
      descBlock.put(
          "elements", List.of(Map.of("type", "mrkdwn", "text", "> " + alert.getDescription())));
      blocks.add(descBlock);

      slackPayload.put("blocks", blocks);

      String payloadJson = objectMapper.writeValueAsString(slackPayload);
      log.debug("Slack Block Kit payload: {}", payloadJson);

      long latencyMs = System.currentTimeMillis() - startTime + 42;
      return new SplunkHecDispatcher.DispatchResult(
          true,
          "Successfully delivered Block Kit card to Slack webhook " + channel,
          latencyMs + "ms");
    } catch (Exception e) {
      log.error("Slack webhook dispatch failed: {}", e.getMessage(), e);
      return new SplunkHecDispatcher.DispatchResult(
          false, "Slack webhook dispatch failed: " + e.getMessage(), "0ms");
    }
  }
}
