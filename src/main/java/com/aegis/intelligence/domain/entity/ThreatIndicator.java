package com.aegis.intelligence.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "threat_indicators")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatIndicator {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(nullable = false, length = 50)
  private String type;

  @Column(nullable = false, unique = true)
  private String indicator;

  @Column(name = "threat_description", nullable = false, columnDefinition = "TEXT")
  private String threatDescription;

  @Column(nullable = false, length = 20)
  private String severity;

  @Column(length = 10)
  private String country;

  @Column(name = "mitre_technique", length = 50)
  private String mitreTechnique;

  @Builder.Default
  @Column(name = "confidence_score", nullable = false)
  private Integer confidenceScore = 85;

  @CreationTimestamp
  @Column(name = "first_seen", nullable = false, updatable = false)
  private Instant firstSeen;

  @UpdateTimestamp
  @Column(name = "last_seen", nullable = false)
  private Instant lastSeen;
}
