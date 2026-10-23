package com.aegis.intelligence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.aegis.intelligence.api.dto.MitreTechniqueStatResponse;
import com.aegis.intelligence.api.dto.ThreatIndicatorResponse;
import com.aegis.intelligence.api.dto.ThreatLookupResponse;
import com.aegis.intelligence.application.service.ThreatIntelService;
import com.aegis.intelligence.domain.entity.ThreatIndicator;
import com.aegis.intelligence.infrastructure.persistence.jpa.ThreatIndicatorJpaRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

@ExtendWith(MockitoExtension.class)
class ThreatIntelServiceTest {

  @Mock private ThreatIndicatorJpaRepository threatIndicatorRepository;

  private ThreatIntelService threatIntelService;

  @BeforeEach
  void setUp() {
    threatIntelService = new ThreatIntelService(threatIndicatorRepository);
  }

  @Test
  @DisplayName("Should lookup known threat indicator and return malicious verdict")
  void shouldLookupKnownThreatIndicator() {
    ThreatIndicator indicator =
        ThreatIndicator.builder()
            .id(UUID.randomUUID())
            .type("IP_REPUTATION")
            .indicator("198.51.100.42")
            .threatDescription("Known Tor Exit Node")
            .severity("HIGH")
            .mitreTechnique("T1078")
            .confidenceScore(92)
            .firstSeen(Instant.now())
            .lastSeen(Instant.now())
            .build();

    when(threatIndicatorRepository.findByIndicatorIgnoreCase("198.51.100.42"))
        .thenReturn(Optional.of(indicator));

    ThreatLookupResponse response = threatIntelService.lookup("198.51.100.42");

    assertThat(response.malicious()).isTrue();
    assertThat(response.riskScore()).isGreaterThanOrEqualTo(80);
    assertThat(response.mitreTechniques()).contains("T1078");
  }

  @Test
  @DisplayName("Should return paginated threat feed")
  void shouldReturnPaginatedFeed() {
    ThreatIndicator indicator =
        ThreatIndicator.builder()
            .id(UUID.randomUUID())
            .type("CVE_EXPLOIT")
            .indicator("CVE-2026-2819")
            .threatDescription("AWS IAM Privilege Escalation")
            .severity("CRITICAL")
            .mitreTechnique("T1098")
            .confidenceScore(96)
            .firstSeen(Instant.now())
            .lastSeen(Instant.now())
            .build();

    when(threatIndicatorRepository.searchIndicators(any(), any(), any(), any()))
        .thenReturn(new PageImpl<>(List.of(indicator)));

    Page<ThreatIndicatorResponse> page =
        threatIntelService.getFeed("CVE", null, null, PageRequest.of(0, 10));

    assertThat(page.getContent()).hasSize(1);
    assertThat(page.getContent().get(0).indicator()).isEqualTo("CVE-2026-2819");
  }

  @Test
  @DisplayName("Should map MITRE ATT&CK technique statistics")
  void shouldMapMitreStatistics() {
    Object[] row = new Object[] {"T1078", 42L};
    when(threatIndicatorRepository.countByMitreTechnique()).thenReturn(List.<Object[]>of(row));

    List<MitreTechniqueStatResponse> stats = threatIntelService.getMitreStats();

    assertThat(stats).hasSize(1);
    assertThat(stats.get(0).code()).isEqualTo("T1078");
    assertThat(stats.get(0).threatCount()).isEqualTo(42L);
  }
}
