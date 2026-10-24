package com.aegis.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuditLogServiceTest {

  @Mock private AuditLogJpaRepository auditLogRepository;
  @Mock private OrganizationJpaRepository organizationRepository;
  @Mock private WorkspaceJpaRepository workspaceRepository;

  @InjectMocks private AuditLogService auditLogService;

  private UUID orgId;
  private Organization organization;
  private AuditLog auditLog;

  @BeforeEach
  void setUp() {
    orgId = UUID.randomUUID();
    organization =
        Organization.builder().id(orgId).name("Aegis Security").slug("aegis-sec").build();

    auditLog =
        AuditLog.builder()
            .id(UUID.randomUUID())
            .organization(organization)
            .actor("admin@aegis.test")
            .action("USER_LOGIN")
            .resource("auth-service")
            .resourceType("IDENTITY")
            .result("SUCCESS")
            .ipAddress("198.51.100.1")
            .details("MFA verified")
            .digestHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .timestamp(Instant.now())
            .build();
  }

  @Test
  @DisplayName("Should record audit log with valid SHA-256 digest hash")
  void shouldRecordAuditWithDigest() {
    when(organizationRepository.findById(orgId)).thenReturn(Optional.of(organization));
    when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(i -> i.getArgument(0));

    AuditLog saved =
        auditLogService.recordAudit(
            orgId,
            null,
            "admin@aegis.test",
            "CONFIG_CHANGE",
            "nexus-connector",
            "CONNECTOR",
            "SUCCESS",
            "127.0.0.1",
            "Updated AWS connector");

    assertThat(saved).isNotNull();
    assertThat(saved.getDigestHash()).isNotNull().hasSize(64);
    verify(auditLogRepository).save(any(AuditLog.class));
  }

  @Test
  @DisplayName("Should export audit logs to RFC-compliant CSV with header")
  void shouldExportToCsv() {
    when(auditLogRepository.findAllByOrganizationIdOrderByTimestampDesc(orgId))
        .thenReturn(List.of(auditLog));

    String csv = auditLogService.exportAuditLogsToCsv(orgId);

    assertThat(csv).isNotNull();
    assertThat(csv)
        .contains(
            "id,timestamp,actor,action,resource,resourceType,result,ipAddress,digestHash,details");
    assertThat(csv).contains("admin@aegis.test");
    assertThat(csv).contains("USER_LOGIN");
    assertThat(csv).contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  }
}
