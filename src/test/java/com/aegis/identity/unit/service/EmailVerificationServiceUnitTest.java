package com.aegis.identity.unit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.common.util.HashUtil;
import com.aegis.identity.application.service.VerifyEmailService;
import com.aegis.identity.domain.entity.EmailVerificationToken;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.EmailVerificationTokenRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceUnitTest {

  @Mock private EmailVerificationTokenRepository tokenRepository;
  @Mock private UserRepository userRepository;
  @Mock private SecurityAuditLogger auditLogger;

  private VerifyEmailService verifyEmailService;
  private User testUser;
  private EmailVerificationToken token;
  private String rawToken;

  @BeforeEach
  void setUp() {
    verifyEmailService = new VerifyEmailService(tokenRepository, userRepository, auditLogger);
    Organization org = Organization.create("Test Org", "test-org");
    testUser = User.create(org, "user@aegis.test", "pwd", "First", "Last");

    rawToken = "raw-token-1234567890";
    String tokenHash = HashUtil.sha256Hex(rawToken);

    token =
        EmailVerificationToken.builder()
            .user(testUser)
            .tokenHash(tokenHash)
            .expiresAt(Instant.now().plus(24, ChronoUnit.HOURS))
            .build();
  }

  @Test
  @DisplayName("VerifyEmailService: Valid token successfully verifies user email")
  void testVerifyEmail_success() {
    when(tokenRepository.findByTokenHash(HashUtil.sha256Hex(rawToken)))
        .thenReturn(Optional.of(token));

    verifyEmailService.execute(rawToken);

    assertThat(testUser.getEmailVerified()).isTrue();
    assertThat(token.isUsed()).isTrue();
    verify(userRepository).save(testUser);
    verify(tokenRepository).save(token);
    verify(auditLogger).logEvent(any());
  }

  @Test
  @DisplayName("VerifyEmailService: Expired token throws IllegalArgumentException")
  void testVerifyEmail_expiredToken_throws() {
    token.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
    when(tokenRepository.findByTokenHash(HashUtil.sha256Hex(rawToken)))
        .thenReturn(Optional.of(token));

    assertThatThrownBy(() -> verifyEmailService.execute(rawToken))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("expired");
  }

  @Test
  @DisplayName("VerifyEmailService: Already used token throws IllegalArgumentException")
  void testVerifyEmail_usedToken_throws() {
    token.setUsedAt(Instant.now().minus(10, ChronoUnit.MINUTES));
    when(tokenRepository.findByTokenHash(HashUtil.sha256Hex(rawToken)))
        .thenReturn(Optional.of(token));

    assertThatThrownBy(() -> verifyEmailService.execute(rawToken))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("already been used");
  }
}
