package com.aegis.audit.domain.entity;

import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.Workspace;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "organization_id", nullable = false)
  private Organization organization;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "workspace_id")
  private Workspace workspace;

  @Column(nullable = false)
  private String actor;

  @Column(nullable = false, length = 100)
  private String action;

  @Column(nullable = false)
  private String resource;

  @Column(name = "resource_type", nullable = false, length = 100)
  private String resourceType;

  @Builder.Default
  @Column(nullable = false, length = 50)
  private String result = "SUCCESS";

  @Column(name = "ip_address", length = 45)
  private String ipAddress;

  @Column(columnDefinition = "TEXT")
  private String details;

  @Column(name = "digest_hash", length = 64)
  private String digestHash;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private Instant timestamp;
}
