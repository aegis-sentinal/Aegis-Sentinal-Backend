package com.aegis.intelligence.infrastructure.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AiModelClient {

  private final String geminiApiKey;
  private final String openaiApiKey;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  public AiModelClient(
      @Value("${aegis.ai.gemini-api-key:${GEMINI_API_KEY:}}") String geminiApiKey,
      @Value("${aegis.ai.openai-api-key:${OPENAI_API_KEY:}}") String openaiApiKey,
      ObjectMapper objectMapper) {
    this.geminiApiKey = geminiApiKey != null ? geminiApiKey.trim() : "";
    this.openaiApiKey = openaiApiKey != null ? openaiApiKey.trim() : "";
    this.objectMapper = objectMapper;
    this.httpClient =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
  }

  public boolean isConfigured() {
    return !geminiApiKey.isEmpty() || !openaiApiKey.isEmpty();
  }

  public String getActiveProviderName() {
    if (!geminiApiKey.isEmpty()) {
      return "Google Gemini (1.5 Flash)";
    }
    if (!openaiApiKey.isEmpty()) {
      return "OpenAI (GPT-4o-mini)";
    }
    return "Helios Neural Engine (Local Ensemble)";
  }

  public Optional<String> generate(String systemPrompt, String userPrompt) {
    if (!geminiApiKey.isEmpty()) {
      try {
        Optional<String> res = callGemini(systemPrompt, userPrompt);
        if (res.isPresent()) {
          return res;
        }
      } catch (Exception e) {
        log.warn("Gemini API call failed, attempting fallback: {}", e.getMessage());
      }
    }

    if (!openaiApiKey.isEmpty()) {
      try {
        Optional<String> res = callOpenAi(systemPrompt, userPrompt);
        if (res.isPresent()) {
          return res;
        }
      } catch (Exception e) {
        log.warn("OpenAI API call failed: {}", e.getMessage());
      }
    }

    return Optional.empty();
  }

  private Optional<String> callGemini(String systemPrompt, String userPrompt) throws Exception {
    String endpoint =
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key="
            + geminiApiKey;

    String combinedText = systemPrompt + "\n\nUser Security Log/Query:\n" + userPrompt;

    Map<String, Object> part = Map.of("text", combinedText);
    Map<String, Object> contentObj = Map.of("parts", List.of(part));
    Map<String, Object> payload =
        Map.of(
            "contents", List.of(contentObj),
            "generationConfig", Map.of("temperature", 0.2));

    String requestJson = objectMapper.writeValueAsString(payload);

    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestJson))
            .timeout(Duration.ofSeconds(20))
            .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() == 200) {
      JsonNode root = objectMapper.readTree(response.body());
      JsonNode candidates = root.path("candidates");
      if (candidates.isArray() && !candidates.isEmpty()) {
        JsonNode parts = candidates.get(0).path("content").path("parts");
        if (parts.isArray() && !parts.isEmpty()) {
          String text = parts.get(0).path("text").asText();
          return Optional.ofNullable(text);
        }
      }
    } else {
      log.warn("Gemini API returned HTTP {}: {}", response.statusCode(), response.body());
    }
    return Optional.empty();
  }

  private Optional<String> callOpenAi(String systemPrompt, String userPrompt) throws Exception {
    String endpoint = "https://api.openai.com/v1/chat/completions";

    Map<String, String> sysMsg = Map.of("role", "system", "content", systemPrompt);
    Map<String, String> userMsg = Map.of("role", "user", "content", userPrompt);

    Map<String, Object> payload =
        Map.of(
            "model", "gpt-4o-mini",
            "messages", List.of(sysMsg, userMsg),
            "temperature", 0.2);

    String requestJson = objectMapper.writeValueAsString(payload);

    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + openaiApiKey)
            .POST(HttpRequest.BodyPublishers.ofString(requestJson))
            .timeout(Duration.ofSeconds(20))
            .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() == 200) {
      JsonNode root = objectMapper.readTree(response.body());
      JsonNode choices = root.path("choices");
      if (choices.isArray() && !choices.isEmpty()) {
        String text = choices.get(0).path("message").path("content").asText();
        return Optional.ofNullable(text);
      }
    } else {
      log.warn("OpenAI API returned HTTP {}: {}", response.statusCode(), response.body());
    }
    return Optional.empty();
  }
}
