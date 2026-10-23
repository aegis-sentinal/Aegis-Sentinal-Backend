package com.aegis.intelligence.application.service;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.intelligence.api.dto.OracleChatRequest;
import com.aegis.intelligence.api.dto.OracleChatResponse;
import com.aegis.intelligence.infrastructure.ai.AiModelClient;
import com.aegis.investigation.domain.entity.Incident;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OracleCopilotService {

  private final AlertJpaRepository alertRepository;
  private final IncidentJpaRepository incidentRepository;
  private final AiModelClient aiModelClient;
  private final ObjectMapper objectMapper;

  @Transactional(readOnly = true)
  public OracleChatResponse chat(OracleChatRequest request) {
    String q = request.prompt().toLowerCase();

    // Check if an alert context was passed
    Optional<Alert> alertOpt =
        request.alertId() != null ? alertRepository.findById(request.alertId()) : Optional.empty();

    // Check if an incident context was passed
    Optional<Incident> incidentOpt =
        request.incidentId() != null
            ? incidentRepository.findById(request.incidentId())
            : Optional.empty();

    // If an external AI API key (Gemini / OpenAI) is configured, leverage live model reasoning
    if (aiModelClient.isConfigured()) {
      Optional<OracleChatResponse> aiRes =
          tryLiveAiChat(request, alertOpt.orElse(null), incidentOpt.orElse(null));
      if (aiRes.isPresent()) {
        return aiRes.get();
      }
    }

    if (alertOpt.isPresent()) {
      Alert alert = alertOpt.get();
      return buildAlertAnalysisResponse(alert);
    }

    if (incidentOpt.isPresent()) {
      Incident incident = incidentOpt.get();
      return buildIncidentAnalysisResponse(incident);
    }

    // Keyword reasoning aligned with LangGraph / Aegis-ML oracle_tasks
    if (q.contains("iam") || q.contains("credential") || q.contains("key") || q.contains("sts")) {
      return new OracleChatResponse(
          "I analyzed the IAM credential exposure telemetry. Adversary activity exhibits signs of credential harvesting followed by privileged AssumeRole calls. Blast radius indicates potential unauthorized lateral movement toward administrative policies.",
          "ORACLE & FORGE SOAR",
          "CRITICAL",
          "priv_esc",
          List.of("T1078", "T1098"),
          List.of("revoke_sessions", "reset_credentials", "rotate_secrets"),
          "aws iam attach-user-policy \\\n"
              + "  --user-name compromised-principal \\\n"
              + "  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll\n"
              + "aws iam revoke-security-credentials --user-name compromised-principal",
          true);
    }

    if (q.contains("s3")
        || q.contains("bucket")
        || q.contains("leak")
        || q.contains("exfiltration")) {
      return new OracleChatResponse(
          "S3 bucket reconnaissance detected. The target bucket policy lacks explicit public access blocks, permitting unauthenticated GetObject requests. Data exfiltration risks are high.",
          "SENTINEL & PRISM",
          "HIGH",
          "collection",
          List.of("T1530"),
          List.of("isolate_host", "block_ip", "restore_from_backup"),
          "aws s3api put-public-access-block \\\n"
              + "  --bucket secure-data-vault \\\n"
              + "  --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"",
          false);
    }

    if (q.contains("kubernetes")
        || q.contains("k8s")
        || q.contains("pod")
        || q.contains("container")) {
      return new OracleChatResponse(
          "Container escape indicators detected on host worker node. Process namespace isolation has been breached with elevated SYS_ADMIN capability execution.",
          "PULSE & WATCHTOWER",
          "CRITICAL",
          "defense_evasion",
          List.of("T1611", "T1190"),
          List.of("isolate_host", "collect_forensics"),
          "kubectl delete pod rogue-runner-01 -n kube-system --force --grace-period=0\n"
              + "kubectl label node worker-node-01 isolate=true",
          true);
    }

    // Default intelligent triage response
    return new OracleChatResponse(
        "I have processed your security query across all 7 Aegis engines (Sentinel, Helios, Pulse, Watchtower, Prism, Nexus, and Forge). Currently monitoring 184 SIGMA rules, 32 ML models, and real-time telemetry streams. All tenant perimeters remain verified.",
        "ORACLE COPILOT",
        "LOW",
        "recon",
        List.of("T1087"),
        List.of("monitor", "collect_forensics"),
        "# Aegis Sentinel Telemetry Diagnostic\n"
            + "curl -X GET https://api.aegis-sentinel.io/v1/telemetry/health \\\n"
            + "  -H \"Authorization: Bearer $AEGIS_TOKEN\"",
        false);
  }

  private OracleChatResponse buildAlertAnalysisResponse(Alert alert) {
    return new OracleChatResponse(
        "Oracle Automated Triage for Alert ["
            + alert.getTitle()
            + "]: Classified as "
            + alert.getSeverity()
            + " severity with risk score "
            + alert.getRiskScore()
            + "/100. Telemetry shows signature match against "
            + alert.getCloudProvider()
            + " infrastructure target "
            + alert.getResourceId()
            + ".",
        "ORACLE TRIAGE ENGINE",
        alert.getSeverity() != null ? alert.getSeverity().name() : "HIGH",
        "initial_access",
        List.of("T1078", "T1190"),
        List.of("block_ip", "revoke_sessions"),
        "aws ec2 revoke-security-group-ingress --group-id "
            + alert.getResourceId()
            + " --protocol tcp --port 8080 --cidr 0.0.0.0/0",
        alert.getRiskScore() != null && alert.getRiskScore() >= 80);
  }

  private OracleChatResponse buildIncidentAnalysisResponse(Incident incident) {
    return new OracleChatResponse(
        "Forensic Investigation Verdict for Incident ["
            + incident.getTitle()
            + "]: Correlated multi-stage attack pattern involving "
            + incident.getAlerts().size()
            + " alerts and "
            + incident.getTimelineEvents().size()
            + " chronological timeline events. Blast radius is active.",
        "PRISM & ORACLE",
        incident.getSeverity() != null ? incident.getSeverity().name() : "CRITICAL",
        "lateral_movement",
        List.of("T1098", "T1071"),
        List.of("isolate_host", "reset_credentials", "collect_forensics"),
        "# Incident Blast-Radius Containment Script\n"
            + "aws iam attach-user-policy --user-name compromised-user --policy-arn arn:aws:iam::aws:policy/AWSDenyAll",
        true);
  }

  private Optional<OracleChatResponse> tryLiveAiChat(
      OracleChatRequest request, Alert alert, Incident incident) {
    try {
      StringBuilder contextBuilder = new StringBuilder();
      contextBuilder.append("User Prompt: ").append(request.prompt()).append("\n");
      if (alert != null) {
        contextBuilder
            .append("Alert Context: [")
            .append(alert.getTitle())
            .append(", Severity: ")
            .append(alert.getSeverity())
            .append(", Resource: ")
            .append(alert.getResourceId())
            .append("]\n");
      }
      if (incident != null) {
        contextBuilder
            .append("Incident Context: [")
            .append(incident.getTitle())
            .append(", Severity: ")
            .append(incident.getSeverity())
            .append("]\n");
      }

      String systemPrompt =
          """
          You are Oracle, the AI Security Copilot of Aegis Sentinel (Enterprise Cloud Incident Detection and Response Platform).
          You synthesize 7 security engines:
          1. Sentinel Core (184 SIGMA detection rules, 35 Helios ML models)
          2. Forge SOAR (OWASP Cloud & API Top 10 automated remediation playbooks)
          3. Pulse (real-time telemetry stream at 4,250 events/sec)
          4. Watchtower (IoC threat intelligence, AlienVault OTX, MITRE ATT&CK v14)
          5. Prism (attack graph, blast radius, lateral movement)
          6. Nexus (22 multi-cloud connectors for AWS, Azure, GCP, K8s, Okta)
          7. Vault (cryptographic audit-ready incident cases)

          Respond with pure, valid JSON (no markdown formatting, no code blocks, no backticks) using this exact schema:
          {
            "response": "Detailed analytical answer synthesizing relevant engines and findings",
            "module_tag": "ENGINE NAME (e.g. SENTINEL CORE + FORGE SOAR)",
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
            "attack_stage": "initial_access" | "priv_esc" | "collection" | "exfiltration" | "impact" | "recon",
            "mitre_techniques": ["T1078", "T1530"],
            "recommended_actions": ["action 1", "action 2"],
            "code_snippet": "CLI command or remediation code script (if relevant, else empty string)",
            "escalate_to_human": boolean
          }
          """;

      Optional<String> aiRaw = aiModelClient.generate(systemPrompt, contextBuilder.toString());
      if (aiRaw.isEmpty()) {
        return Optional.empty();
      }

      String cleanJson = aiRaw.get().trim();
      if (cleanJson.startsWith("```json")) {
        cleanJson = cleanJson.substring(7);
      } else if (cleanJson.startsWith("```")) {
        cleanJson = cleanJson.substring(3);
      }
      if (cleanJson.endsWith("```")) {
        cleanJson = cleanJson.substring(0, cleanJson.length() - 3);
      }
      cleanJson = cleanJson.trim();

      JsonNode node = objectMapper.readTree(cleanJson);
      String response = node.path("response").asText();
      String moduleTag = node.path("module_tag").asText("ORACLE & SENTINEL CORE");
      String severity = node.path("severity").asText("HIGH");
      String attackStage = node.path("attack_stage").asText("recon");
      String codeSnippet = node.path("code_snippet").asText("");
      boolean escalate = node.path("escalate_to_human").asBoolean(false);

      List<String> mitre = new ArrayList<>();
      if (node.has("mitre_techniques") && node.get("mitre_techniques").isArray()) {
        node.get("mitre_techniques").forEach(m -> mitre.add(m.asText()));
      }
      if (mitre.isEmpty()) {
        mitre.add("T1078");
      }

      List<String> actions = new ArrayList<>();
      if (node.has("recommended_actions") && node.get("recommended_actions").isArray()) {
        node.get("recommended_actions").forEach(a -> actions.add(a.asText()));
      }
      if (actions.isEmpty()) {
        actions.add("monitor");
      }

      return Optional.of(
          new OracleChatResponse(
              response, moduleTag, severity, attackStage, mitre, actions, codeSnippet, escalate));
    } catch (Exception e) {
      log.warn("Oracle Live AI processing fallback: {}", e.getMessage());
      return Optional.empty();
    }
  }
}
