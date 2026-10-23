package com.aegis.nexus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.common.exception.ResourceNotFoundException;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.nexus.api.dto.IntegrationConnectorResponse;
import com.aegis.nexus.api.dto.UpdateConnectorStatusRequest;
import com.aegis.nexus.application.service.NexusIntegrationService;
import com.aegis.nexus.domain.entity.IntegrationConnector;
import com.aegis.nexus.domain.model.IntegrationCategory;
import com.aegis.nexus.domain.model.IntegrationStatus;
import com.aegis.nexus.infrastructure.persistence.IntegrationConnectorJpaRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NexusIntegrationServiceTest {

  @Mock private IntegrationConnectorJpaRepository connectorRepository;

  @InjectMocks private NexusIntegrationService nexusIntegrationService;

  private UUID orgId;
  private Organization organization;
  private IntegrationConnector connector;

  @BeforeEach
  void setUp() {
    orgId = UUID.randomUUID();
    organization = Organization.builder().id(orgId).name("Test Org").slug("test-org").build();

    connector =
        IntegrationConnector.builder()
            .id(UUID.randomUUID())
            .connectorKey("aws")
            .organization(organization)
            .name("Amazon Web Services")
            .category(IntegrationCategory.CLOUD)
            .status(IntegrationStatus.CONNECTED)
            .description("AWS CloudTrail Ingest")
            .latency("120ms")
            .lastSync(Instant.now())
            .config("{\"region\":\"us-east-1\"}")
            .build();
  }

  @Test
  @DisplayName("Should list all integration connectors for an organization")
  void shouldListConnectors() {
    when(connectorRepository.findAllByOrganizationId(orgId)).thenReturn(List.of(connector));

    List<IntegrationConnectorResponse> results = nexusIntegrationService.getConnectors(orgId, null);

    assertThat(results).hasSize(1);
    assertThat(results.get(0).connectorKey()).isEqualTo("aws");
    assertThat(results.get(0).category()).isEqualTo(IntegrationCategory.CLOUD);
  }

  @Test
  @DisplayName("Should get connector by key")
  void shouldGetConnectorByKey() {
    when(connectorRepository.findByOrganizationIdAndConnectorKey(orgId, "aws"))
        .thenReturn(Optional.of(connector));

    IntegrationConnectorResponse result = nexusIntegrationService.getConnectorByKey(orgId, "aws");

    assertThat(result.connectorKey()).isEqualTo("aws");
    assertThat(result.name()).isEqualTo("Amazon Web Services");
  }

  @Test
  @DisplayName("Should throw ResourceNotFoundException when connector key is unknown")
  void shouldThrowWhenConnectorKeyNotFound() {
    when(connectorRepository.findByOrganizationIdAndConnectorKey(orgId, "unknown"))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> nexusIntegrationService.getConnectorByKey(orgId, "unknown"))
        .isInstanceOf(ResourceNotFoundException.class);
  }

  @Test
  @DisplayName("Should update connector status and sync timestamp")
  void shouldUpdateConnectorStatus() {
    when(connectorRepository.findByOrganizationIdAndConnectorKey(orgId, "aws"))
        .thenReturn(Optional.of(connector));
    when(connectorRepository.save(any(IntegrationConnector.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    UpdateConnectorStatusRequest request =
        new UpdateConnectorStatusRequest(IntegrationStatus.INACTIVE);
    IntegrationConnectorResponse response =
        nexusIntegrationService.updateStatus(orgId, "aws", request);

    assertThat(response.status()).isEqualTo(IntegrationStatus.INACTIVE);
    verify(connectorRepository).save(connector);
  }

  @Test
  @DisplayName("Should test connector connection health")
  void shouldTestConnectorConnection() {
    when(connectorRepository.findByOrganizationIdAndConnectorKey(orgId, "aws"))
        .thenReturn(Optional.of(connector));
    when(connectorRepository.save(any(IntegrationConnector.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    IntegrationConnectorResponse response = nexusIntegrationService.testConnection(orgId, "aws");

    assertThat(response.status()).isEqualTo(IntegrationStatus.CONNECTED);
    assertThat(response.latency()).isEqualTo("110ms");
    assertThat(response.lastSync()).isNotNull();
  }
}
