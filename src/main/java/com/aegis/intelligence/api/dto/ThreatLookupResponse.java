package com.aegis.intelligence.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ThreatLookupResponse(
    String indicator,
    Boolean malicious,
    @JsonProperty("risk_score") Integer riskScore,
    String category,
    String reputation,
    @JsonProperty("mitre_techniques") List<String> mitreTechniques,
    String recommendation) {}
