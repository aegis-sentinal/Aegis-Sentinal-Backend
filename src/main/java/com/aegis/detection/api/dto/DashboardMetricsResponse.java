package com.aegis.detection.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record DashboardMetricsResponse(
    @JsonProperty("total_alerts") long totalAlerts,
    @JsonProperty("critical_alerts") long criticalAlerts,
    @JsonProperty("open_alerts") long openAlerts,
    @JsonProperty("resolved_alerts") long resolvedAlerts,
    @JsonProperty("avg_resolution_time_ms") long avgResolutionTimeMs,
    @JsonProperty("mttr_minutes") int mttrMinutes,
    @JsonProperty("threat_level") String threatLevel,
    @JsonProperty("auto_remediation_rate") double autoRemediationRate) {}
