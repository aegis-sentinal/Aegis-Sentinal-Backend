package com.aegis.identity.application.service;

import com.aegis.identity.application.port.RefreshTokenHasher;
import com.aegis.identity.application.port.TokenService;
import com.aegis.identity.application.query.AuthenticationResult;
import com.aegis.identity.domain.entity.Session;
import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.SessionRepository;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CreateSessionService {

  private final SessionRepository sessionRepository;
  private final RefreshTokenHasher refreshTokenHasher;
  private final TokenService tokenService;

  public CreateSessionService(
      SessionRepository sessionRepository,
      RefreshTokenHasher refreshTokenHasher,
      TokenService tokenService) {

    this.sessionRepository = sessionRepository;
    this.refreshTokenHasher = refreshTokenHasher;
    this.tokenService = tokenService;
  }

  @Transactional
  public Session create(User user, String refreshToken) {
    String tokenHash = refreshTokenHasher.hash(refreshToken);
    Session session = Session.create(user, tokenHash);
    return sessionRepository.save(session);
  }

  @Transactional
  public AuthenticationResult issueTokensAndCreateSession(User user) {
    return issueTokensAndCreateSession(user, List.of("pwd"));
  }

  @Transactional
  public AuthenticationResult issueTokensAndCreateSession(User user, List<String> amr) {
    String accessToken = tokenService.generateAccessToken(user, amr);
    String refreshToken = tokenService.generateRefreshToken(user);

    create(user, refreshToken);

    return new AuthenticationResult(accessToken, refreshToken);
  }
}
