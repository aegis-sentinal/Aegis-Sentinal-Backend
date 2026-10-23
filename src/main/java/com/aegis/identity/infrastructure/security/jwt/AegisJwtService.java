package com.aegis.identity.infrastructure.security.jwt;

import com.aegis.identity.application.port.TokenService;
import com.aegis.identity.domain.entity.User;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Service
public class AegisJwtService implements TokenService {

  private final JwtEncoder jwtEncoder;
  private final JwtDecoder jwtDecoder;
  private final JwtProperties properties;

  public AegisJwtService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, JwtProperties properties) {
    this.jwtEncoder = jwtEncoder;
    this.jwtDecoder = jwtDecoder;
    this.properties = properties;
  }

  @Override
  public String generateAccessToken(User user) {
    return generateAccessToken(user, List.of("pwd"));
  }

  @Override
  public String generateAccessToken(User user, List<String> amr) {
    Instant issuedAt = Instant.now();

    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer(properties.issuer())
            .subject(user.getId().toString())
            .issuedAt(issuedAt)
            .expiresAt(issuedAt.plus(properties.accessTokenTtl()))
            .claim("email", user.getEmail())
            .claim("token_type", "access")
            .claim("amr", amr != null ? amr : List.of("pwd"))
            .build();

    return encode(claims);
  }

  @Override
  public String generateRefreshToken(User user) {
    Instant issuedAt = Instant.now();

    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer(properties.issuer())
            .subject(user.getId().toString())
            .id(UUID.randomUUID().toString())
            .issuedAt(issuedAt)
            .expiresAt(issuedAt.plus(properties.refreshTokenTtl()))
            .claim("token_type", "refresh")
            .build();

    return encode(claims);
  }

  @Override
  public UUID extractUserIdFromRefreshToken(String refreshToken) {
    try {
      Jwt jwt = jwtDecoder.decode(refreshToken);
      String tokenType = jwt.getClaimAsString("token_type");
      if (!"refresh".equals(tokenType)) {
        throw new IllegalArgumentException("Invalid token type: expected refresh token");
      }
      return UUID.fromString(jwt.getSubject());
    } catch (JwtException | IllegalArgumentException ex) {
      throw new IllegalArgumentException("Invalid or expired refresh token", ex);
    }
  }

  private String encode(JwtClaimsSet claims) {
    JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
    return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
  }
}
