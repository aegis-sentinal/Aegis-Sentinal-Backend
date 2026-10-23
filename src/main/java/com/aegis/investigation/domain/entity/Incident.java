package com.aegis.investigation.domain.entity;

import com.aegis.detection.domain.entity.Alert;
import com.aegis.detection.domain.model.AlertSeverity;
import com.aegis.detection.domain.model.CloudProvider;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.entity.Workspace;
import com.aegis.investigation.domain.model.IncidentStatus;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "incidents")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Incident {

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
  private String title;

  @Column(columnDefinition = "TEXT")
  private String summary;

  @Column(nullable = false, length = 20)
  private AlertSeverity severity;

  @Builder.Default
  @Column(nullable = false, length = 50)
  private IncidentStatus status = IncidentStatus.NEW;

  @Builder.Default
  @Column(name = "risk_score", nullable = false)
  private Integer riskScore = 50;

  @Builder.Default
  @Column(name = "cloud_provider", nullable = false, length = 50)
  private CloudProvider cloudProvider = CloudProvider.AWS;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "assigned_to")
  private User assignedTo;

  @Builder.Default
  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(
      name = "incident_alerts",
      joinColumns = @JoinColumn(name = "incident_id"),
      inverseJoinColumns = @JoinColumn(name = "alert_id"))
  private Set<Alert> alerts = new HashSet<>();

  @Builder.Default
  @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true)
  @OrderBy("timestamp ASC")
  private List<TimelineEvent> timelineEvents = new ArrayList<>();

  @Builder.Default
  @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true)
  private List<EvidenceArtifact> evidenceArtifacts = new ArrayList<>();

  @Builder.Default
  @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true)
  @OrderBy("createdAt ASC")
  private List<IncidentComment> comments = new ArrayList<>();

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  @Column(name = "closed_at")
  private Instant closedAt;
}
