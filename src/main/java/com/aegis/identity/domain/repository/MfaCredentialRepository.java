package com.aegis.identity.domain.repository;

import com.aegis.identity.domain.entity.MfaCredential;
import java.util.Optional;
import java.util.UUID;

public interface MfaCredentialRepository {

  MfaCredential save(MfaCredential credential);

  Optional<MfaCredential> findByUserId(UUID userId);

  void deleteByUserId(UUID userId);
}
