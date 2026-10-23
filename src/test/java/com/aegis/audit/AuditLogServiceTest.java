package com.aegis.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.application.service.AuditLogService;
import com.aegis.audit.domain.entity.AuditLog;
import com.aegis.audit.infrastructure.persistence.jpa.AuditLogJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.infrastructure.persistence.jpa.OrganizationJpaRepository;
import com.aegis.identity.infrastructure.persistence.jpa.WorkspaceJpaRepository;
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
class AuditLogServiceTest {

  @Mock private AuditLogJpaRepository auditLogRepository;
  @Mock private OrganizationJpaRepository organizationRepository;
  @Mock private WorkspaceJpaRepository workspaceRepository;

  private AuditLogService auditLogService;
  private UUID orgId;
  private Organization testOrg;

  @BeforeEach
  void setUp() {
    auditLogService =
        new AuditLogService(auditLogRepository, organizationRepository, workspaceRepository);
    orgId = UUID.randomUUID();
    testOrg = Organization.builder().id(orgId).name("Acme").slug("acme").build();
  }

  @Test
  @DisplayName("Should query paginated audit logs for organization")
  void shouldQueryAuditLogs() {
    AuditLog log =
        AuditLog.builder()
            .id(UUID.randomUUID())
            .organization(testOrg)
            .actor("admin@acme.com")
            .action("USER_LOGIN")
            .resource("auth-service")
            .resourceType("IDENTITY")
            .result("SUCCESS")
            .digestHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .timestamp(Instant.now())
            .build();

    when(auditLogRepository.searchAuditLogs(any(), any(), any(), any(), any()))
        .thenReturn(new PageImpl<>(List.of(log)));

    Page<AuditLogResponse> page =
        auditLogService.getAuditLogs(orgId, null, null, null, PageRequest.of(0, 10));

    assertThat(page.getContent()).hasSize(1);
    assertThat(page.getContent().get(0).actor()).isEqualTo("admin@acme.com");
  }

  @Test
  @DisplayName("Should record audit entry with computed SHA-256 digest")
  void shouldRecordAuditEntryWithDigest() {
    when(organizationRepository.findById(orgId)).thenReturn(Optional.of(testOrg));
    when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(inv -> inv.getArgument(0));

    AuditLog saved =
        auditLogService.recordAudit(
            orgId,
            null,
            "analyst@acme.com",
            "REMEDIATION_TRIGGER",
            "sg-12345",
            "SECURITY_GROUP",
            "SUCCESS",
            "192.168.1.1",
            "Revoked ingress");

    assertThat(saved).isNotNull();
    assertThat(saved.getDigestHash()).isNotEmpty();
    assertThat(saved.getDigestHash()).hasSize(64);
    verify(auditLogRepository).save(any(AuditLog.class));
  }
}
