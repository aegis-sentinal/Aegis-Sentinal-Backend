package com.aegis.intelligence.infrastructure.persistence.jpa;

import com.aegis.intelligence.domain.entity.ThreatIndicator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIndicatorJpaRepository extends JpaRepository<ThreatIndicator, UUID> {

  Optional<ThreatIndicator> findByIndicatorIgnoreCase(String indicator);

  @Query(
      "SELECT t FROM ThreatIndicator t WHERE "
          + "(:search IS NULL OR LOWER(t.indicator) LIKE LOWER(CONCAT('%', :search, '%')) "
          + "OR LOWER(t.threatDescription) LIKE LOWER(CONCAT('%', :search, '%')) "
          + "OR LOWER(t.mitreTechnique) LIKE LOWER(CONCAT('%', :search, '%'))) AND "
          + "(:type IS NULL OR LOWER(t.type) = LOWER(:type)) AND "
          + "(:severity IS NULL OR LOWER(t.severity) = LOWER(:severity))")
  Page<ThreatIndicator> searchIndicators(
      @Param("search") String search,
      @Param("type") String type,
      @Param("severity") String severity,
      Pageable pageable);

  @Query("SELECT t.mitreTechnique, COUNT(t) FROM ThreatIndicator t GROUP BY t.mitreTechnique")
  List<Object[]> countByMitreTechnique();
}
