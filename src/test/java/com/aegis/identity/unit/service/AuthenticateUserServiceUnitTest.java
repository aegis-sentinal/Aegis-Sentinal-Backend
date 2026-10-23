package com.aegis.identity.unit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.aegis.identity.application.command.LoginUserCommand;
import com.aegis.identity.application.port.PasswordHasher;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.application.query.LoginExecutionResult;
import com.aegis.identity.application.service.AuthenticateUserService;
import com.aegis.identity.application.service.CreateSessionService;
import com.aegis.identity.domain.entity.MfaChallenge;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaChallengeRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthenticateUserServiceUnitTest {

  @Mock private UserRepository userRepository;
  @Mock private PasswordHasher passwordHasher;
  @Mock private CreateSessionService createSessionService;
  @Mock private MfaChallengeRepository mfaChallengeRepository;
  @Mock private SecurityAuditLogger auditLogger;

  private AuthenticateUserService service;
  private User testUser;

  @BeforeEach
  void setUp() {
    service =
        new AuthenticateUserService(
            userRepository,
            passwordHasher,
            createSessionService,
            mfaChallengeRepository,
            auditLogger);
    Organization org = Organization.create("Test Org", "test-org");
    testUser = User.create(org, "user@aegis.test", "hashed_pwd", "Test", "User");
    testUser.setEmailVerified(true);
  }

  @Test
  @DisplayName(
      "Service Unit Test: Successful password authentication issues tokens and logs audit event when MFA disabled")
  void testExecute_success() {
    LoginUserCommand cmd = new LoginUserCommand("user@aegis.test", "Password123!");
    when(userRepository.findByEmail("user@aegis.test")).thenReturn(Optional.of(testUser));
    when(passwordHasher.matches("Password123!", "hashed_pwd")).thenReturn(true);
    when(createSessionService.issueTokensAndCreateSession(testUser, List.of("pwd")))
        .thenReturn(new AuthenticationResult("access_token", "refresh_token"));

    LoginExecutionResult result = service.execute(cmd);

    assertThat(result.status()).isEqualTo("SUCCESS");
    assertThat(result.authenticationResult().accessToken()).isEqualTo("access_token");
    assertThat(result.authenticationResult().refreshToken()).isEqualTo("refresh_token");
    verify(auditLogger).logEvent(any());
  }

  @Test
  @DisplayName("Service Unit Test: MFA enabled issues MFA_REQUIRED challenge")
  void testExecute_mfaEnabled() {
    testUser.setIsMfaEnabled(true);
    LoginUserCommand cmd = new LoginUserCommand("user@aegis.test", "Password123!");
    when(userRepository.findByEmail("user@aegis.test")).thenReturn(Optional.of(testUser));
    when(passwordHasher.matches("Password123!", "hashed_pwd")).thenReturn(true);
    when(mfaChallengeRepository.save(any()))
        .thenAnswer(
            invocation -> {
              MfaChallenge c = invocation.getArgument(0);
              c.setId(UUID.randomUUID());
              return c;
            });

    LoginExecutionResult result = service.execute(cmd);

    assertThat(result.status()).isEqualTo("MFA_REQUIRED");
    assertThat(result.challengeId()).isNotNull();
    assertThat(result.expiresIn()).isEqualTo(300L);
  }

  @Test
  @DisplayName("Service Unit Test: Email unverified throws IllegalStateException")
  void testExecute_emailUnverified_throws() {
    testUser.setEmailVerified(false);
    LoginUserCommand cmd = new LoginUserCommand("user@aegis.test", "Password123!");
    when(userRepository.findByEmail("user@aegis.test")).thenReturn(Optional.of(testUser));
    when(passwordHasher.matches("Password123!", "hashed_pwd")).thenReturn(true);

    assertThatThrownBy(() -> service.execute(cmd))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Email verification required");
  }

  @Test
  @DisplayName("Service Unit Test: Unknown email throws IllegalArgumentException")
  void testExecute_unknownEmail_throws() {
    LoginUserCommand cmd = new LoginUserCommand("unknown@aegis.test", "Password123!");
    when(userRepository.findByEmail("unknown@aegis.test")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.execute(cmd))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid email or password");
  }

  @Test
  @DisplayName("Service Unit Test: Inactive user throws IllegalStateException")
  void testExecute_inactiveUser_throws() {
    testUser.setIsActive(false);
    LoginUserCommand cmd = new LoginUserCommand("user@aegis.test", "Password123!");
    when(userRepository.findByEmail("user@aegis.test")).thenReturn(Optional.of(testUser));

    assertThatThrownBy(() -> service.execute(cmd))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("inactive");
  }

  @Test
  @DisplayName("Service Unit Test: Wrong password throws IllegalArgumentException")
  void testExecute_wrongPassword_throws() {
    LoginUserCommand cmd = new LoginUserCommand("user@aegis.test", "WrongPassword!");
    when(userRepository.findByEmail("user@aegis.test")).thenReturn(Optional.of(testUser));
    when(passwordHasher.matches("WrongPassword!", "hashed_pwd")).thenReturn(false);

    assertThatThrownBy(() -> service.execute(cmd))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid email or password");
  }
}
