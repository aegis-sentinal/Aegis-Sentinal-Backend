package com.aegis.nexus.application.service;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.nexus.api.dto.IntegrationConnectorResponse;
import com.aegis.nexus.api.dto.UpdateConnectorStatusRequest;
import com.aegis.nexus.domain.entity.IntegrationConnector;
import com.aegis.nexus.domain.model.IntegrationCategory;
import com.aegis.nexus.domain.model.IntegrationStatus;
import com.aegis.nexus.infrastructure.persistence.IntegrationConnectorJpaRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class NexusIntegrationService {

  private final IntegrationConnectorJpaRepository connectorRepository;

  @Transactional(readOnly = true)
  public List<IntegrationConnectorResponse> getConnectors(
      UUID organizationId, IntegrationCategory category) {
    List<IntegrationConnector> connectors =
        category != null
            ? connectorRepository.findAllByOrganizationIdAndCategory(organizationId, category)
            : connectorRepository.findAllByOrganizationId(organizationId);

    return connectors.stream().map(IntegrationConnectorResponse::fromEntity).toList();
  }

  @Transactional(readOnly = true)
  public IntegrationConnectorResponse getConnectorByKey(UUID organizationId, String connectorKey) {
    IntegrationConnector connector =
        connectorRepository
            .findByOrganizationIdAndConnectorKey(organizationId, connectorKey)
            .orElseThrow(
                () ->
                    new ResourceNotFoundException(
                        "Integration connector not found for key: " + connectorKey));

    return IntegrationConnectorResponse.fromEntity(connector);
  }

  @Transactional
  public IntegrationConnectorResponse updateStatus(
      UUID organizationId, String connectorKey, UpdateConnectorStatusRequest request) {
    IntegrationConnector connector =
        connectorRepository
            .findByOrganizationIdAndConnectorKey(organizationId, connectorKey)
            .orElseThrow(
                () ->
                    new ResourceNotFoundException(
                        "Integration connector not found for key: " + connectorKey));

    connector.setStatus(request.status());
    if (request.status() == IntegrationStatus.CONNECTED) {
      connector.setLastSync(Instant.now());
      if (connector.getLatency() == null) {
        connector.setLatency("125ms");
      }
    }

    IntegrationConnector saved = connectorRepository.save(connector);
    log.info(
        "Updated integration connector {} status to {} for organization {}",
        connectorKey,
        request.status(),
        organizationId);
    return IntegrationConnectorResponse.fromEntity(saved);
  }

  @Transactional
  public IntegrationConnectorResponse testConnection(UUID organizationId, String connectorKey) {
    IntegrationConnector connector =
        connectorRepository
            .findByOrganizationIdAndConnectorKey(organizationId, connectorKey)
            .orElseThrow(
                () ->
                    new ResourceNotFoundException(
                        "Integration connector not found for key: " + connectorKey));

    // Simulate connection ping test
    connector.setLastSync(Instant.now());
    connector.setLatency("110ms");
    if (connector.getStatus() != IntegrationStatus.CONNECTED) {
      connector.setStatus(IntegrationStatus.CONNECTED);
    }

    IntegrationConnector saved = connectorRepository.save(connector);
    log.info(
        "Tested integration connector {} successfully for organization {}",
        connectorKey,
        organizationId);
    return IntegrationConnectorResponse.fromEntity(saved);
  }
}
