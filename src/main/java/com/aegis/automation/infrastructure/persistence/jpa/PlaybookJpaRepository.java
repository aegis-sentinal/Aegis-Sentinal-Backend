package com.aegis.automation.infrastructure.persistence.jpa;

import com.aegis.automation.domain.entity.Playbook;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PlaybookJpaRepository extends JpaRepository<Playbook, UUID> {

  List<Playbook> findByIsEnabledTrue();
}
