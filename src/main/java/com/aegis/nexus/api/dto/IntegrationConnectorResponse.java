package com.aegis.nexus.api.dto;

import com.aegis.nexus.domain.entity.IntegrationConnector;
import com.aegis.nexus.domain.model.IntegrationCategory;
import com.aegis.nexus.domain.model.IntegrationStatus;
import java.time.Instant;
import java.util.UUID;
import lombok.Builder;

@Builder
public record IntegrationConnectorResponse(
    UUID id,
    String connectorKey,
    String name,
    IntegrationCategory category,
    IntegrationStatus status,
    String description,
    String latency,
    Instant lastSync,
    String config,
    Instant createdAt,
    Instant updatedAt) {

  public static IntegrationConnectorResponse fromEntity(IntegrationConnector entity) {
    return IntegrationConnectorResponse.builder()
        .id(entity.getId())
        .connectorKey(entity.getConnectorKey())
        .name(entity.getName())
        .category(entity.getCategory())
        .status(entity.getStatus())
        .description(entity.getDescription())
        .latency(entity.getLatency())
        .lastSync(entity.getLastSync())
        .config(entity.getConfig())
        .createdAt(entity.getCreatedAt())
        .updatedAt(entity.getUpdatedAt())
        .build();
  }
}
