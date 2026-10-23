package com.aegis.intelligence.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record OracleChatResponse(
    String response,
    @JsonProperty("module_tag") String moduleTag,
    String severity,
    @JsonProperty("attack_stage") String attackStage,
    @JsonProperty("mitre_techniques") List<String> mitreTechniques,
    @JsonProperty("recommended_actions") List<String> recommendedActions,
    @JsonProperty("code_snippet") String codeSnippet,
    @JsonProperty("escalate_to_human") Boolean escalateToHuman) {}
