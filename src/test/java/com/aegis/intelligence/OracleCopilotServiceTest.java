package com.aegis.intelligence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.detection.infrastructure.persistence.jpa.AlertJpaRepository;
import com.aegis.intelligence.api.dto.OracleChatRequest;
import com.aegis.intelligence.api.dto.OracleChatResponse;
import com.aegis.intelligence.application.service.OracleCopilotService;
import com.aegis.investigation.infrastructure.persistence.jpa.IncidentJpaRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OracleCopilotServiceTest {

  @Mock private AlertJpaRepository alertRepository;
  @Mock private IncidentJpaRepository incidentRepository;

  private OracleCopilotService oracleCopilotService;

  @BeforeEach
  void setUp() {
    oracleCopilotService = new OracleCopilotService(alertRepository, incidentRepository);
  }

  @Test
  @DisplayName("Should answer IAM credential question with remediation code")
  void shouldAnswerIamSecurityQuestion() {
    OracleChatRequest request =
        new OracleChatRequest("How do I respond to exposed IAM keys?", null, null);

    OracleChatResponse response = oracleCopilotService.chat(request);

    assertThat(response.severity()).isEqualTo("CRITICAL");
    assertThat(response.attackStage()).isEqualTo("priv_esc");
    assertThat(response.mitreTechniques()).contains("T1078");
    assertThat(response.codeSnippet()).contains("aws iam");
    assertThat(response.escalateToHuman()).isTrue();
  }

  @Test
  @DisplayName("Should perform alert context triage when alert ID provided")
  void shouldPerformAlertContextTriage() {
    UUID alertId = UUID.randomUUID();
    Alert alert =
        Alert.builder()
            .id(alertId)
            .title("Suspicious AssumeRole Activity")
            .severity(AlertSeverity.CRITICAL)
            .riskScore(92)
            .cloudProvider(CloudProvider.AWS)
            .resourceId("i-091f27c8230")
            .build();

    when(alertRepository.findById(alertId)).thenReturn(Optional.of(alert));

    OracleChatRequest request = new OracleChatRequest("Investigate alert", alertId, null);
    OracleChatResponse response = oracleCopilotService.chat(request);

    assertThat(response.response()).contains("Suspicious AssumeRole Activity");
    assertThat(response.severity()).isEqualTo("CRITICAL");
    assertThat(response.escalateToHuman()).isTrue();
  }
}
