package com.aegis.identity.application.service;

import com.aegis.identity.application.port.OAuthUserInfo;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.domain.entity.Organization;
import com.aegis.identity.domain.entity.Role;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.entity.UserIdentity;
import com.aegis.identity.domain.entity.UserRole;
import com.aegis.identity.domain.entity.Workspace;
import com.aegis.identity.domain.repository.OrganizationRepository;
import com.aegis.identity.domain.repository.RoleRepository;
import com.aegis.identity.domain.repository.UserIdentityRepository;
import com.aegis.identity.domain.repository.UserRepository;
import com.aegis.identity.domain.repository.UserRoleRepository;
import com.aegis.identity.domain.repository.WorkspaceRepository;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OAuthOnboardingService {

  private final OrganizationRepository organizationRepository;
  private final WorkspaceRepository workspaceRepository;
  private final UserRepository userRepository;
  private final UserIdentityRepository userIdentityRepository;
  private final RoleRepository roleRepository;
  private final UserRoleRepository userRoleRepository;
  private final CreateSessionService createSessionService;

  public OAuthOnboardingService(
      OrganizationRepository organizationRepository,
      WorkspaceRepository workspaceRepository,
      UserRepository userRepository,
      UserIdentityRepository userIdentityRepository,
      RoleRepository roleRepository,
      UserRoleRepository userRoleRepository,
      CreateSessionService createSessionService) {

    this.organizationRepository = organizationRepository;
    this.workspaceRepository = workspaceRepository;
    this.userRepository = userRepository;
    this.userIdentityRepository = userIdentityRepository;
    this.roleRepository = roleRepository;
    this.userRoleRepository = userRoleRepository;
    this.createSessionService = createSessionService;
  }

  @Transactional
  public AuthenticationResult execute(OAuthUserInfo userInfo) {
    String baseName = StringUtils.defaultIfBlank(userInfo.firstName(), "User") + "'s Organization";
    String slug = generateSlug(baseName, userInfo.email());

    Organization org = organizationRepository.save(Organization.create(baseName, slug));

    Workspace workspace =
        workspaceRepository.save(Workspace.create(org, "Default Workspace", "default"));

    User user =
        User.builder()
            .organization(org)
            .email(userInfo.email())
            .passwordHash("$2a$10$UnusablePasswordForOAuthUserPlaceholderSecretHash")
            .firstName(userInfo.firstName())
            .lastName(userInfo.lastName())
            .isActive(true)
            .isMfaEnabled(false)
            .emailVerified(true)
            .build();

    user = userRepository.save(user);

    UserIdentity identity =
        new UserIdentity(user, userInfo.provider(), userInfo.providerSubject(), userInfo.email());
    userIdentityRepository.save(identity);

    Role orgAdminRole =
        roleRepository
            .findByName("ORG_ADMIN")
            .orElseThrow(() -> new IllegalStateException("ORG_ADMIN role missing in system seed"));

    UserRole userRole = UserRole.create(user, orgAdminRole, org, workspace);
    userRoleRepository.save(userRole);

    return createSessionService.issueTokensAndCreateSession(user, List.of("oauth"));
  }

  private String generateSlug(String name, String email) {
    String base =
        name.toLowerCase()
            .replaceAll("[^a-z0-9]", "-")
            .replaceAll("-+", "-")
            .replaceAll("^-|-$", "");
    if (base.isBlank()) {
      base = email.split("@")[0].toLowerCase().replaceAll("[^a-z0-9]", "-");
    }
    String slug = base;
    int count = 1;
    while (organizationRepository.existsBySlug(slug)) {
      slug = base + "-" + count++;
    }
    return slug;
  }
}
