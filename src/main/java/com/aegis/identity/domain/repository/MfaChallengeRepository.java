package com.aegis.identity.domain.repository;

import com.aegis.identity.domain.entity.MfaChallenge;
import java.util.Optional;
import java.util.UUID;

public interface MfaChallengeRepository {

  MfaChallenge save(MfaChallenge challenge);

  Optional<MfaChallenge> findById(UUID id);

  void deleteByUserId(UUID userId);
}
