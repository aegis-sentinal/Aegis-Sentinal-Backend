package com.aegis.audit.application.service;

import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.domain.entity.AuditLog;
import com.aegis.audit.infrastructure.persistence.jpa.AuditLogJpaRepository;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.Workspace;
import com.aegis.identity.infrastructure.persistence.jpa.OrganizationJpaRepository;
import com.aegis.identity.infrastructure.persistence.jpa.WorkspaceJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

  private final AuditLogJpaRepository auditLogRepository;
  private final OrganizationJpaRepository organizationRepository;
  private final WorkspaceJpaRepository workspaceRepository;

  @Transactional(readOnly = true)
  public Page<AuditLogResponse> getAuditLogs(
      UUID organizationId, String actor, String action, String result, Pageable pageable) {
    return auditLogRepository
        .searchAuditLogs(organizationId, actor, action, result, pageable)
        .map(AuditLogResponse::fromEntity);
  }

  @Transactional
  public AuditLog recordAudit(
      UUID organizationId,
      UUID workspaceId,
      String actor,
      String action,
      String resource,
      String resourceType,
      String result,
      String ipAddress,
      String details) {

    Organization org = organizationRepository.findById(organizationId).orElse(null);
    if (org == null) {
      log.warn("Cannot record audit log for nonexistent organization {}", organizationId);
      return null;
    }

    Workspace ws =
        workspaceId != null ? workspaceRepository.findById(workspaceId).orElse(null) : null;

    String digestInput = actor + ":" + action + ":" + resource + ":" + result + ":" + details;
    String hash = computeSha256(digestInput);

    AuditLog entry =
        AuditLog.builder()
            .organization(org)
            .workspace(ws)
            .actor(actor)
            .action(action)
            .resource(resource)
            .resourceType(resourceType)
            .result(result != null ? result.toUpperCase() : "SUCCESS")
            .ipAddress(ipAddress)
            .details(details)
            .digestHash(hash)
            .build();

    return auditLogRepository.save(entry);
  }

  private String computeSha256(String input) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (NoSuchAlgorithmException e) {
      return "0000000000000000000000000000000000000000000000000000000000000000";
    }
  }
}
