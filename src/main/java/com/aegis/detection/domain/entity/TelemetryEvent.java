package com.aegis.detection.domain.entity;

import com.aegis.detection.domain.model.CloudProvider;
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
@Table(name = "telemetry_events")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TelemetryEvent {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "organization_id", nullable = false)
  private Organization organization;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "workspace_id")
  private Workspace workspace;

  @Column(name = "event_id")
  private String eventId;

  @Column(name = "event_source", nullable = false, length = 100)
  private String eventSource;

  @Column(name = "event_name", nullable = false, length = 100)
  private String eventName;

  @Column(name = "principal_id")
  private String principalId;

  @Column(name = "source_ip", length = 45)
  private String sourceIp;

  @Column(name = "destination_resource")
  private String destinationResource;

  @Builder.Default
  @Column(name = "cloud_provider", nullable = false, length = 50)
  private CloudProvider cloudProvider = CloudProvider.AWS;

  @Column(name = "raw_payload", columnDefinition = "TEXT")
  private String rawPayload;

  @Builder.Default
  @Column(nullable = false)
  private Boolean processed = false;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "matched_rule_id")
  private DetectionRule matchedRule;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private Instant timestamp;
}
