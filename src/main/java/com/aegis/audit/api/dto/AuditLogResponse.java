package com.aegis.audit.api.dto;

import com.aegis.audit.domain.entity.AuditLog;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

public record AuditLogResponse(
    UUID id,
    String actor,
    String action,
    String resource,
    @JsonProperty("resource_type") String resourceType,
    String result,
    @JsonProperty("ip_address") String ipAddress,
    String details,
    @JsonProperty("digest_hash") String digestHash,
    Instant timestamp) {

  public static AuditLogResponse fromEntity(AuditLog log) {
    return new AuditLogResponse(
        log.getId(),
        log.getActor(),
        log.getAction(),
        log.getResource(),
        log.getResourceType(),
        log.getResult() != null ? log.getResult().toLowerCase() : "success",
        log.getIpAddress(),
        log.getDetails(),
        log.getDigestHash(),
        log.getTimestamp());
  }
}
