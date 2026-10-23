package com.aegis.identity.api.controller;

import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.identity.api.dto.AuthenticationResponse;
import com.aegis.identity.api.dto.GenericMessageResponse;
import com.aegis.identity.api.dto.LinkAccountRequest;
import com.aegis.identity.api.dto.LoginRequest;
import com.aegis.identity.api.dto.LogoutRequest;
import com.aegis.identity.api.dto.MfaRecoveryRequest;
import com.aegis.identity.api.dto.MfaVerifyChallengeRequest;
import com.aegis.identity.api.dto.OrganizationResponse;
import com.aegis.identity.api.dto.RefreshTokenRequest;
import com.aegis.identity.api.dto.RegisterRequest;
import com.aegis.identity.api.dto.ResendVerificationRequest;
import com.aegis.identity.api.dto.UserResponse;
import com.aegis.identity.api.dto.VerifyEmailRequest;
import com.aegis.identity.api.dto.WorkspaceResponse;
import com.aegis.identity.application.command.LinkAccountCommand;
import com.aegis.identity.application.command.LoginUserCommand;
import com.aegis.identity.application.command.LogoutCommand;
import com.aegis.identity.application.command.RefreshTokenCommand;
import com.aegis.identity.application.command.RegisterOrganizationCommand;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.application.query.LoginExecutionResult;
import com.aegis.identity.application.query.UserContext;
import com.aegis.identity.application.service.AuthenticateUserService;
import com.aegis.identity.application.service.GetCurrentUserService;
import com.aegis.identity.application.service.LogoutService;
import com.aegis.identity.application.service.OAuthAccountLinkService;
import com.aegis.identity.application.service.RefreshTokenService;
import com.aegis.identity.application.service.RegisterOrganizationService;
import com.aegis.identity.application.service.ResendEmailVerificationService;
import com.aegis.identity.application.service.VerifyEmailService;
import com.aegis.identity.application.service.VerifyMfaChallengeService;
import com.aegis.identity.application.service.VerifyMfaRecoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Authentication",
    description =
        "Endpoints for user registration, email verification, login authentication, MFA challenges, token refresh, and profile queries")
@RestController
@RequestMapping("/api/aegis/v1/auth")
public class AuthController {

  private final RegisterOrganizationService registerOrganizationService;
  private final AuthenticateUserService authenticateUserService;
  private final RefreshTokenService refreshTokenService;
  private final LogoutService logoutService;
  private final GetCurrentUserService getCurrentUserService;
  private final OAuthAccountLinkService oAuthAccountLinkService;
  private final VerifyEmailService verifyEmailService;
  private final ResendEmailVerificationService resendEmailVerificationService;
  private final VerifyMfaChallengeService verifyMfaChallengeService;
  private final VerifyMfaRecoveryService verifyMfaRecoveryService;

  public AuthController(
      RegisterOrganizationService registerOrganizationService,
      AuthenticateUserService authenticateUserService,
      RefreshTokenService refreshTokenService,
      LogoutService logoutService,
      GetCurrentUserService getCurrentUserService,
      OAuthAccountLinkService oAuthAccountLinkService,
      VerifyEmailService verifyEmailService,
      ResendEmailVerificationService resendEmailVerificationService,
      VerifyMfaChallengeService verifyMfaChallengeService,
      VerifyMfaRecoveryService verifyMfaRecoveryService) {

    this.registerOrganizationService = registerOrganizationService;
    this.authenticateUserService = authenticateUserService;
    this.refreshTokenService = refreshTokenService;
    this.logoutService = logoutService;
    this.getCurrentUserService = getCurrentUserService;
    this.oAuthAccountLinkService = oAuthAccountLinkService;
    this.verifyEmailService = verifyEmailService;
    this.resendEmailVerificationService = resendEmailVerificationService;
    this.verifyMfaChallengeService = verifyMfaChallengeService;
    this.verifyMfaRecoveryService = verifyMfaRecoveryService;
  }

  @Operation(
      summary = "Register organization & admin user",
      description =
          "Creates a new tenant organization, workspace, and administrator user account. Dispatches a verification email prior to issuing tokens.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "201",
            description = "Organization registered; verification email sent",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthenticationResponse.class))),
        @ApiResponse(
            responseCode = "400",
            description = "Validation failed or organization/user already exists",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/register")
  @ResponseStatus(HttpStatus.CREATED)
  public AuthenticationResponse register(@Valid @RequestBody RegisterRequest request) {

    registerOrganizationService.execute(
        new RegisterOrganizationCommand(
            request.organizationName(),
            request.organizationSlug(),
            request.workspaceName(),
            request.workspaceSlug(),
            request.email(),
            request.password(),
            request.firstName(),
            request.lastName()));

    return AuthenticationResponse.registrationPending(
        "Registration successful. Please check your email to verify your account.");
  }

  @Operation(
      summary = "User login with email and password",
      description =
          "Authenticates user credentials. Returns JWT tokens if MFA is disabled, or an MFA_REQUIRED challenge if MFA is enabled.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Authentication successful or MFA challenge issued",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthenticationResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Invalid credentials, unverified email, or unauthorized",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/login")
  public AuthenticationResponse login(@Valid @RequestBody LoginRequest request) {

    LoginExecutionResult result =
        authenticateUserService.execute(new LoginUserCommand(request.email(), request.password()));

    if ("MFA_REQUIRED".equals(result.status())) {
      return AuthenticationResponse.mfaRequired(
          result.challengeId().toString(), result.expiresIn());
    }

    AuthenticationResult authResult = result.authenticationResult();
    return new AuthenticationResponse(
        authResult.accessToken(), authResult.refreshToken(), "Bearer");
  }

  @Operation(
      summary = "Verify user email address",
      description = "Consumes a raw verification token to activate user email ownership.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Email verified successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = GenericMessageResponse.class))),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid, expired, or already used verification token",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/verify-email")
  public GenericMessageResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
    verifyEmailService.execute(request.token());
    return new GenericMessageResponse("Email verified successfully");
  }

  @Operation(
      summary = "Resend email verification token",
      description =
          "Dispatches a new email verification token if the account exists and requires verification.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Generic status message returned to prevent email enumeration",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = GenericMessageResponse.class)))
      })
  @PostMapping("/resend-verification")
  public GenericMessageResponse resendVerification(
      @Valid @RequestBody ResendVerificationRequest request) {
    resendEmailVerificationService.execute(request.email());
    return new GenericMessageResponse(
        "If the account exists and requires verification, a verification email has been sent.");
  }

  @Operation(
      summary = "Verify 6-digit TOTP code for MFA login challenge",
      description =
          "Verifies a 6-digit authenticator TOTP code for an active login challenge and issues JWT tokens.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "MFA verification successful; JWT tokens issued",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthenticationResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Invalid TOTP code, expired challenge, or exceeded attempts limit",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/mfa/verify")
  public AuthenticationResponse verifyMfa(@Valid @RequestBody MfaVerifyChallengeRequest request) {
    AuthenticationResult result =
        verifyMfaChallengeService.execute(request.challengeId(), request.code());
    return new AuthenticationResponse(result.accessToken(), result.refreshToken(), "Bearer");
  }

  @Operation(
      summary = "Verify recovery code for MFA login challenge",
      description =
          "Consumes a single-use recovery code for an active login challenge and issues JWT tokens.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Recovery code consumed successfully; JWT tokens issued",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthenticationResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Invalid recovery code or expired challenge",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/mfa/recovery")
  public AuthenticationResponse verifyMfaRecovery(@Valid @RequestBody MfaRecoveryRequest request) {
    AuthenticationResult result =
        verifyMfaRecoveryService.execute(request.challengeId(), request.recoveryCode());
    return new AuthenticationResponse(result.accessToken(), result.refreshToken(), "Bearer");
  }

  @Operation(
      summary = "Refresh access token",
      description =
          "Exchanges a valid refresh token for a newly issued access token and rotated refresh token.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Token refreshed successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthenticationResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Invalid, expired, or revoked refresh token",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/refresh")
  public AuthenticationResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {

    AuthenticationResult result =
        refreshTokenService.execute(new RefreshTokenCommand(request.refreshToken()));

    return new AuthenticationResponse(result.accessToken(), result.refreshToken(), "Bearer");
  }

  @Operation(
      summary = "User logout",
      description = "Revokes user session and invalidates refresh token.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "204", description = "Logout successful (No Content)"),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid refresh token format",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/logout")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void logout(@Valid @RequestBody LogoutRequest request) {

    logoutService.execute(new LogoutCommand(request.refreshToken()));
  }

  @Tag(name = "OAuth")
  @Operation(
      summary = "Link OAuth provider account",
      description =
          "Links a Google or third-party OAuth provider identity to an existing password user account.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Account linked successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthenticationResponse.class))),
        @ApiResponse(
            responseCode = "409",
            description = "Account already linked to another provider subject",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/link-account")
  public AuthenticationResponse linkAccount(@Valid @RequestBody LinkAccountRequest request) {

    AuthenticationResult result =
        oAuthAccountLinkService.execute(
            new LinkAccountCommand(request.email(), request.password(), request.providerSubject()));

    return new AuthenticationResponse(result.accessToken(), result.refreshToken(), "Bearer");
  }

  @Operation(
      summary = "Get current authenticated user context",
      description =
          "Retrieves active user profile, tenant organization, workspace, assigned roles, and granted fine-grained permissions.",
      security = @SecurityRequirement(name = "bearerAuth"))
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "User context retrieved successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthenticated or invalid JWT access token",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping("/me")
  public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
    if (jwt == null
        || jwt.getSubject() == null
        || !"access".equals(jwt.getClaimAsString("token_type"))) {
      throw new IllegalArgumentException("Unauthenticated request");
    }

    UUID userId = UUID.fromString(jwt.getSubject());
    UserContext context = getCurrentUserService.execute(userId);

    OrganizationResponse orgResponse =
        context.organization() != null
            ? new OrganizationResponse(
                context.organization().getId(),
                context.organization().getName(),
                context.organization().getSlug())
            : null;

    WorkspaceResponse wsResponse =
        context.workspace() != null
            ? new WorkspaceResponse(
                context.workspace().getId(),
                context.workspace().getName(),
                context.workspace().getSlug())
            : null;

    return new UserResponse(
        context.user().getId(),
        context.user().getEmail(),
        context.user().getFirstName(),
        context.user().getLastName(),
        orgResponse,
        wsResponse,
        context.roles(),
        context.permissions());
  }
}
