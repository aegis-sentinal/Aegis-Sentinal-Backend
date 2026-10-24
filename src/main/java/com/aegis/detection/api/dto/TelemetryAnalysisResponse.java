package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record TelemetryAnalysisResponse(
    @JsonProperty("verdict") String verdict,
    @JsonProperty("fusedAnomalyScore") double fusedAnomalyScore,
    @JsonProperty("confidencePercent") double confidencePercent,
    @JsonProperty("mitreTactic") String mitreTactic,
    @JsonProperty("mitreTechnique") String mitreTechnique,
    @JsonProperty("summary") String summary,
    @JsonProperty("totalPipelineLatencyMs") double totalPipelineLatencyMs,
    @JsonProperty("overallAccuracy") double overallAccuracy,
    @JsonProperty("overallPrecision") double overallPrecision,
    @JsonProperty("overallRecall") double overallRecall,
    @JsonProperty("overallF1") double overallF1,
    @JsonProperty("falsePositiveRate") double falsePositiveRate,
    @JsonProperty("formatDetected") String formatDetected,
    @JsonProperty("aiProviderUsed") String aiProviderUsed,
    @JsonProperty("modelsUsed") List<ModelMetricDto> modelsUsed,
    @JsonProperty("matchedSigmaRules") List<MatchedSigmaRuleDto> matchedSigmaRules,
    @JsonProperty("extractedEntities") ExtractedEntitiesDto extractedEntities) {}
