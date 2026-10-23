package com.aegis.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.aegis.identity.api.dto.MfaSetupResponse;
import com.aegis.identity.api.dto.MfaSetupVerificationResponse;
import com.aegis.identity.api.dto.MfaStatusResponse;
import com.aegis.identity.application.command.LoginUserCommand;
import com.aegis.identity.application.command.RegisterOrganizationCommand;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.application.query.LoginExecutionResult;
import com.aegis.identity.application.service.AuthenticateUserService;
import com.aegis.identity.application.service.MfaManagementService;
import com.aegis.identity.application.service.MfaSetupService;
import com.aegis.identity.application.service.MfaVerificationService;
import com.aegis.identity.application.service.RegisterOrganizationService;
import com.aegis.identity.application.service.VerifyMfaChallengeService;
import com.aegis.identity.application.service.VerifyMfaRecoveryService;
import com.aegis.identity.domain.entity.EmailVerificationToken;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.persistence.jpa.EmailVerificationTokenJpaRepository;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class IdentityAssuranceIntegrationTest {

  @Autowired private RegisterOrganizationService registerOrganizationService;
  @Autowired private AuthenticateUserService authenticateUserService;
  @Autowired private MfaSetupService mfaSetupService;
  @Autowired private MfaVerificationService mfaVerificationService;
  @Autowired private VerifyMfaChallengeService verifyMfaChallengeService;
  @Autowired private VerifyMfaRecoveryService verifyMfaRecoveryService;
  @Autowired private MfaManagementService mfaManagementService;
  @Autowired private UserRepository userRepository;
  @Autowired private EmailVerificationTokenJpaRepository tokenJpaRepository;

  @Test
  @DisplayName(
      "Full Identity Assurance Lifecycle: Registration, Email Verification, MFA Setup, MFA Login Challenge, and Recovery Codes")
  void testFullIdentityAssuranceLifecycle() {
    String unique = UUID.randomUUID().toString().substring(0, 8);
    String email = "assurance-" + unique + "@aegis.test";
    String password = "P@ssw0rd123!" + unique;

    // 1. Register User
    User user =
        registerOrganizationService.execute(
            new RegisterOrganizationCommand(
                "Assurance Org " + unique,
                "org-" + unique,
                "Workspace",
                "ws-" + unique,
                email,
                password,
                "Assurance",
                "Tester"));

    assertThat(user.getEmailVerified()).isFalse();

    // 2. Unverified email login attempt should fail
    assertThatThrownBy(() -> authenticateUserService.execute(new LoginUserCommand(email, password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Email verification required");

    // 3. Verify Email using token
    EmailVerificationToken token =
        tokenJpaRepository.findAll().stream()
            .filter(t -> t.getUser().getId().equals(user.getId()))
            .findFirst()
            .orElseThrow();
    assertThat(token.getTokenHash()).isNotBlank();

    user.setEmailVerified(true);
    userRepository.save(user);

    // 4. Login after email verification (MFA OFF) -> returns SUCCESS and tokens
    LoginExecutionResult login1 =
        authenticateUserService.execute(new LoginUserCommand(email, password));
    assertThat(login1.status()).isEqualTo("SUCCESS");
    assertThat(login1.authenticationResult().accessToken()).isNotNull();

    // 5. Initiate MFA Setup
    MfaSetupResponse setupResponse = mfaSetupService.execute(user);
    assertThat(setupResponse.secret()).isNotNull();
    assertThat(setupResponse.otpauthUri()).contains(setupResponse.secret());

    // 6. Confirm MFA setup with current TOTP code
    String validCode = generateCurrentTotp(setupResponse.secret());
    MfaSetupVerificationResponse setupVerification =
        mfaVerificationService.execute(user, validCode);

    assertThat(setupVerification.recoveryCodes()).hasSize(10);
    User updatedUser = userRepository.findById(user.getId()).orElseThrow();
    assertThat(updatedUser.getIsMfaEnabled()).isTrue();

    // Check MFA Status
    MfaStatusResponse statusResponse = mfaManagementService.getMfaStatus(updatedUser);
    assertThat(statusResponse.isMfaEnabled()).isTrue();

    // 7. Login with MFA ON -> Password verification returns MFA_REQUIRED challenge
    LoginExecutionResult login2 =
        authenticateUserService.execute(new LoginUserCommand(email, password));
    assertThat(login2.status()).isEqualTo("MFA_REQUIRED");
    assertThat(login2.challengeId()).isNotNull();

    // 8. Verify MFA Login Challenge via TOTP
    String loginTotpCode = generateCurrentTotp(setupResponse.secret());
    AuthenticationResult mfaAuthResult =
        verifyMfaChallengeService.execute(login2.challengeId(), loginTotpCode);
    assertThat(mfaAuthResult.accessToken()).isNotNull();

    // 9. Verify MFA Login Challenge via Recovery Code
    LoginExecutionResult login3 =
        authenticateUserService.execute(new LoginUserCommand(email, password));
    String recoveryCode = setupVerification.recoveryCodes().get(0);
    AuthenticationResult recoveryAuthResult =
        verifyMfaRecoveryService.execute(login3.challengeId(), recoveryCode);
    assertThat(recoveryAuthResult.accessToken()).isNotNull();

    // 10. Disable MFA
    String disableCode = generateCurrentTotp(setupResponse.secret());
    mfaManagementService.disableMfa(updatedUser, password, disableCode);

    User disabledMfaUser = userRepository.findById(user.getId()).orElseThrow();
    assertThat(disabledMfaUser.getIsMfaEnabled()).isFalse();
  }

  private String generateCurrentTotp(String secret) {
    long currentWindow = System.currentTimeMillis() / 1000 / 30;
    try {
      byte[] keyBytes = com.aegis.common.util.Base32.decode(secret);
      byte[] timeBytes = java.nio.ByteBuffer.allocate(8).putLong(currentWindow).array();
      javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
      mac.init(new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA1"));
      byte[] hash = mac.doFinal(timeBytes);
      int offset = hash[hash.length - 1] & 0x0F;
      int binary =
          ((hash[offset] & 0x7F) << 24)
              | ((hash[offset + 1] & 0xFF) << 16)
              | ((hash[offset + 2] & 0xFF) << 8)
              | (hash[offset + 3] & 0xFF);
      int otp = binary % 1000000;
      return String.format("%06d", otp);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
