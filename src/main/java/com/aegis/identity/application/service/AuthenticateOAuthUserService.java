package com.aegis.identity.application.service;

import com.aegis.identity.application.port.OAuthIdentityProvider;
import com.aegis.identity.application.port.OAuthUserInfo;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.application.query.OAuthAuthenticationResult;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.entity.UserIdentity;
import com.aegis.identity.domain.repository.UserIdentityRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.infrastructure.security.oauth.OAuthIdentityProviderRegistry;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticateOAuthUserService {

  private final OAuthIdentityProviderRegistry identityProviderRegistry;
  private final UserIdentityRepository userIdentityRepository;
  private final UserRepository userRepository;
  private final OAuthOnboardingService oAuthOnboardingService;
  private final CreateSessionService createSessionService;

  public AuthenticateOAuthUserService(
      OAuthIdentityProviderRegistry identityProviderRegistry,
      UserIdentityRepository userIdentityRepository,
      UserRepository userRepository,
      OAuthOnboardingService oAuthOnboardingService,
      CreateSessionService createSessionService) {

    this.identityProviderRegistry = identityProviderRegistry;
    this.userIdentityRepository = userIdentityRepository;
    this.userRepository = userRepository;
    this.oAuthOnboardingService = oAuthOnboardingService;
    this.createSessionService = createSessionService;
  }

  @Transactional
  public OAuthAuthenticationResult execute(Object principal) {
    OAuthIdentityProvider provider = identityProviderRegistry.resolve(principal);
    OAuthUserInfo userInfo = provider.extractUserInfo(principal);

    Optional<UserIdentity> existingIdentity =
        userIdentityRepository.findByProviderAndProviderSubject(
            userInfo.provider(), userInfo.providerSubject());

    if (existingIdentity.isPresent()) {
      User user = existingIdentity.get().getUser();
      if (!user.isActive()) {
        throw new IllegalStateException("User account is inactive");
      }
      if (!Boolean.TRUE.equals(user.getEmailVerified())) {
        user.setEmailVerified(true);
        userRepository.save(user);
      }

      return OAuthAuthenticationResult.success(
          createSessionService.issueTokensAndCreateSession(user, List.of("oauth")));
    }

    Optional<User> existingUserByEmail = userRepository.findByEmail(userInfo.email());
    if (existingUserByEmail.isPresent()) {
      return OAuthAuthenticationResult.linkingRequired(userInfo);
    }

    AuthenticationResult onboardingResult = oAuthOnboardingService.execute(userInfo);
    return OAuthAuthenticationResult.success(onboardingResult);
  }
}
