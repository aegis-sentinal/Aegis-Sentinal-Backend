package com.aegis.identity.api.controller;

import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.identity.api.dto.GenericMessageResponse;
import com.aegis.identity.api.dto.MfaDisableRequest;
import com.aegis.identity.api.dto.MfaRegenerateCodesRequest;
import com.aegis.identity.api.dto.MfaSetupResponse;
import com.aegis.identity.api.dto.MfaSetupVerificationResponse;
import com.aegis.identity.api.dto.MfaStatusResponse;
import com.aegis.identity.api.dto.MfaVerifySetupRequest;
import com.aegis.identity.application.service.MfaManagementService;
import com.aegis.identity.application.service.MfaSetupService;
import com.aegis.identity.application.service.MfaVerificationService;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "MFA Management",
    description =
        "Authenticated endpoints for MFA enrollment, status queries, recovery code management, and MFA disablement")
@RestController
@RequestMapping("/api/aegis/v1/auth/mfa")
@SecurityRequirement(name = "bearerAuth")
public class MfaController {

  private final MfaSetupService mfaSetupService;
  private final MfaVerificationService mfaVerificationService;
  private final MfaManagementService mfaManagementService;
  private final UserRepository userRepository;

  public MfaController(
      MfaSetupService mfaSetupService,
      MfaVerificationService mfaVerificationService,
      MfaManagementService mfaManagementService,
      UserRepository userRepository) {
    this.mfaSetupService = mfaSetupService;
    this.mfaVerificationService = mfaVerificationService;
    this.mfaManagementService = mfaManagementService;
    this.userRepository = userRepository;
  }

  @Operation(
      summary = "Get MFA status for current user",
      description = "Returns whether MFA is currently enabled for the authenticated user account.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "MFA status retrieved successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = MfaStatusResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthenticated request",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping("/status")
  public MfaStatusResponse getStatus(@AuthenticationPrincipal Jwt jwt) {
    User user = extractAuthenticatedUser(jwt);
    return mfaManagementService.getMfaStatus(user);
  }

  @Operation(
      summary = "Initiate MFA setup",
      description =
          "Generates a new Base32 secret key and otpauth URI for authenticator QR code scanning.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "MFA setup initiated successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = MfaSetupResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthenticated request",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/setup")
  public MfaSetupResponse setup(@AuthenticationPrincipal Jwt jwt) {
    User user = extractAuthenticatedUser(jwt);
    return mfaSetupService.execute(user);
  }

  @Operation(
      summary = "Confirm MFA setup",
      description =
          "Verifies initial 6-digit TOTP code, enables MFA, and generates 10 single-use recovery codes.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "MFA setup confirmed and enabled; recovery codes returned",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = MfaSetupVerificationResponse.class))),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid TOTP code supplied",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/verify-setup")
  public MfaSetupVerificationResponse verifySetup(
      @AuthenticationPrincipal Jwt jwt, @Valid @RequestBody MfaVerifySetupRequest request) {
    User user = extractAuthenticatedUser(jwt);
    return mfaVerificationService.execute(user, request.code());
  }

  @Operation(
      summary = "Disable MFA for current user",
      description = "Requires current user password and valid TOTP code to disable MFA protection.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "MFA disabled successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = GenericMessageResponse.class))),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid password or TOTP code",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/disable")
  public GenericMessageResponse disable(
      @AuthenticationPrincipal Jwt jwt, @Valid @RequestBody MfaDisableRequest request) {
    User user = extractAuthenticatedUser(jwt);
    mfaManagementService.disableMfa(user, request.password(), request.code());
    return new GenericMessageResponse("MFA disabled successfully");
  }

  @Operation(
      summary = "Regenerate MFA recovery codes",
      description =
          "Invalidates existing recovery codes and generates 10 new single-use codes after TOTP verification.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "New recovery codes generated successfully",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = MfaSetupVerificationResponse.class))),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid TOTP code or MFA not enabled",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/regenerate-recovery-codes")
  public MfaSetupVerificationResponse regenerateRecoveryCodes(
      @AuthenticationPrincipal Jwt jwt, @Valid @RequestBody MfaRegenerateCodesRequest request) {
    User user = extractAuthenticatedUser(jwt);
    return mfaManagementService.regenerateRecoveryCodes(user, request.code());
  }

  private User extractAuthenticatedUser(Jwt jwt) {
    if (jwt == null || jwt.getSubject() == null) {
      throw new IllegalArgumentException("Unauthenticated request");
    }
    UUID userId = UUID.fromString(jwt.getSubject());
    return userRepository
        .findById(userId)
        .orElseThrow(() -> new IllegalArgumentException("User not found"));
  }
}
