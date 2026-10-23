package com.aegis.nexus.infrastructure.persistence;

import com.aegis.nexus.domain.entity.IntegrationConnector;
import com.aegis.nexus.domain.model.IntegrationCategory;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IntegrationConnectorJpaRepository
    extends JpaRepository<IntegrationConnector, UUID> {

  List<IntegrationConnector> findAllByOrganizationId(UUID organizationId);

  List<IntegrationConnector> findAllByOrganizationIdAndCategory(
      UUID organizationId, IntegrationCategory category);

  Optional<IntegrationConnector> findByOrganizationIdAndConnectorKey(
      UUID organizationId, String connectorKey);

  Optional<IntegrationConnector> findByOrganizationIdAndId(UUID organizationId, UUID id);
}
