package com.aegis.intelligence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.intelligence.application.service.ThreatFeedIngestionService;
import com.aegis.intelligence.domain.entity.ThreatIndicator;
import com.aegis.intelligence.infrastructure.persistence.jpa.ThreatIndicatorJpaRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ThreatFeedIngestionServiceTest {

  @Mock private ThreatIndicatorJpaRepository threatIndicatorRepository;

  private ThreatFeedIngestionService feedService;

  @BeforeEach
  void setUp() {
    feedService = new ThreatFeedIngestionService(threatIndicatorRepository);
  }

  @Test
  @DisplayName("syncFeeds ingests new OSINT indicators and updates existing records")
  void syncFeeds_success() {
    ThreatIndicator existingIndicator =
        ThreatIndicator.builder()
            .id(UUID.randomUUID())
            .type("IP_REPUTATION")
            .indicator("198.51.100.42")
            .confidenceScore(80)
            .severity("HIGH")
            .firstSeen(Instant.now().minusSeconds(3600))
            .lastSeen(Instant.now().minusSeconds(1800))
            .build();

    when(threatIndicatorRepository.findByIndicatorIgnoreCase("198.51.100.42"))
        .thenReturn(Optional.of(existingIndicator));

    when(threatIndicatorRepository.save(any(ThreatIndicator.class)))
        .thenAnswer(i -> i.getArgument(0));

    ThreatFeedIngestionService.FeedSyncResult result = feedService.syncFeeds();

    assertThat(result).isNotNull();
    assertThat(result.totalSynced()).isGreaterThan(10);
    assertThat(result.updated()).isGreaterThanOrEqualTo(1);
    assertThat(result.newlyAdded()).isGreaterThan(0);
    verify(threatIndicatorRepository, atLeastOnce()).save(any(ThreatIndicator.class));
  }

  @Test
  @DisplayName("checkIndicator returns matched indicator when present")
  void checkIndicator_returnsMatch() {
    ThreatIndicator indicator =
        ThreatIndicator.builder()
            .id(UUID.randomUUID())
            .type("IP_REPUTATION")
            .indicator("198.51.100.42")
            .threatDescription("Tor exit node")
            .confidenceScore(90)
            .build();

    when(threatIndicatorRepository.findByIndicatorIgnoreCase("198.51.100.42"))
        .thenReturn(Optional.of(indicator));

    Optional<ThreatIndicator> match = feedService.checkIndicator("198.51.100.42");

    assertThat(match).isPresent();
    assertThat(match.get().getThreatDescription()).isEqualTo("Tor exit node");
  }
}
