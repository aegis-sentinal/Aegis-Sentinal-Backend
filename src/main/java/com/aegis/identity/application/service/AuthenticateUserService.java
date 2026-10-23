package com.aegis.identity.application.service;

import com.aegis.identity.application.command.LoginUserCommand;
import com.aegis.identity.application.port.PasswordHasher;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.application.query.LoginExecutionResult;
import com.aegis.identity.domain.entity.MfaChallenge;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.MfaChallengeRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.audit.AuditEventType;
import com.aegis.identity.infrastructure.audit.SecurityAuditEvent;
import com.aegis.identity.infrastructure.audit.SecurityAuditLogger;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticateUserService {

  private final UserRepository userRepository;
  private final PasswordHasher passwordHasher;
  private final CreateSessionService createSessionService;
  private final MfaChallengeRepository mfaChallengeRepository;
  private final SecurityAuditLogger auditLogger;

  public AuthenticateUserService(
      UserRepository userRepository,
      PasswordHasher passwordHasher,
      CreateSessionService createSessionService,
      MfaChallengeRepository mfaChallengeRepository,
      SecurityAuditLogger auditLogger) {
    this.userRepository = userRepository;
    this.passwordHasher = passwordHasher;
    this.createSessionService = createSessionService;
    this.mfaChallengeRepository = mfaChallengeRepository;
    this.auditLogger = auditLogger;
  }

  @Transactional
  public LoginExecutionResult execute(LoginUserCommand command) {

    User user =
        userRepository
            .findByEmail(command.email())
            .orElseThrow(
                () -> {
                  auditLogger.logEvent(
                      SecurityAuditEvent.of(
                          AuditEventType.AUTH_LOGIN_FAILURE,
                          null,
                          "FAILURE",
                          "User login failed: Email not found"));
                  return new IllegalArgumentException("Invalid email or password");
                });

    if (!user.isActive()) {
      throw new IllegalStateException("User account is inactive");
    }

    if (!passwordHasher.matches(command.password(), user.getPasswordHash())) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.AUTH_LOGIN_FAILURE,
              user.getId(),
              "FAILURE",
              "User login failed: Incorrect password"));
      throw new IllegalArgumentException("Invalid email or password");
    }

    if (!Boolean.TRUE.equals(user.getEmailVerified())) {
      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.AUTH_LOGIN_FAILURE,
              user.getId(),
              "FAILURE",
              "User login failed: Email unverified"));
      throw new IllegalStateException(
          "Email verification required. Please verify your email before logging in.");
    }

    if (Boolean.TRUE.equals(user.getIsMfaEnabled())) {
      MfaChallenge challenge =
          MfaChallenge.builder()
              .user(user)
              .expiresAt(Instant.now().plusSeconds(300))
              .attempts(0)
              .build();

      challenge = mfaChallengeRepository.save(challenge);

      auditLogger.logEvent(
          SecurityAuditEvent.of(
              AuditEventType.AUTH_LOGIN_SUCCESS,
              user.getId(),
              "PENDING_MFA",
              "Password verified, MFA challenge issued"));

      return LoginExecutionResult.mfaRequired(challenge.getId(), 300);
    }

    AuthenticationResult result =
        createSessionService.issueTokensAndCreateSession(user, List.of("pwd"));
    auditLogger.logEvent(
        SecurityAuditEvent.of(
            AuditEventType.AUTH_LOGIN_SUCCESS,
            user.getId(),
            "SUCCESS",
            "Local password login successful"));

    return LoginExecutionResult.success(result);
  }
}
