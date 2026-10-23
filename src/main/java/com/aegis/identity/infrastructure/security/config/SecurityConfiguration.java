package com.aegis.identity.infrastructure.security.config;

import com.aegis.identity.infrastructure.security.authorization.DatabaseGrantedAuthoritiesConverter;
import com.aegis.identity.infrastructure.security.jwt.JwtProperties;
import com.aegis.identity.infrastructure.security.oauth.OAuth2FailureHandler;
import com.aegis.identity.infrastructure.security.oauth.OAuth2SuccessHandler;
import com.aegis.identity.infrastructure.security.ratelimit.RateLimitingFilter;
import com.aegis.identity.infrastructure.security.tenant.TenantResolverFilter;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfiguration {

  private final DatabaseGrantedAuthoritiesConverter authoritiesConverter;
  private final TenantResolverFilter tenantResolverFilter;
  private final OAuth2SuccessHandler oAuth2SuccessHandler;
  private final OAuth2FailureHandler oAuth2FailureHandler;
  private final RateLimitingFilter rateLimitingFilter;
  private final List<String> allowedOrigins;

  public SecurityConfiguration(
      DatabaseGrantedAuthoritiesConverter authoritiesConverter,
      TenantResolverFilter tenantResolverFilter,
      OAuth2SuccessHandler oAuth2SuccessHandler,
      OAuth2FailureHandler oAuth2FailureHandler,
      RateLimitingFilter rateLimitingFilter,
      @Value("${aegis.security.cors.allowed-origins:http://localhost:3000,http://localhost:5173}")
          String allowedOriginsStr) {

    this.authoritiesConverter = authoritiesConverter;
    this.tenantResolverFilter = tenantResolverFilter;
    this.oAuth2SuccessHandler = oAuth2SuccessHandler;
    this.oAuth2FailureHandler = oAuth2FailureHandler;
    this.rateLimitingFilter = rateLimitingFilter;
    this.allowedOrigins = Arrays.asList(allowedOriginsStr.split(","));
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig)
      throws Exception {
    return authConfig.getAuthenticationManager();
  }

  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
    return converter;
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(allowedOrigins);
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(
        List.of(
            "Authorization",
            "Content-Type",
            "X-Organization-Id",
            "X-Workspace-Id",
            "X-Requested-With"));
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(csrf -> csrf.disable())
        .headers(
            headers ->
                headers
                    .frameOptions(frame -> frame.deny())
                    .contentTypeOptions(Customizer.withDefaults())
                    .referrerPolicy(
                        referrer ->
                            referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                    .addHeaderWriter(
                        new org.springframework.security.web.header.writers.StaticHeadersWriter(
                            "Permissions-Policy", "geolocation=(), camera=(), microphone=()")))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(
                        "/actuator/health/**",
                        "/oauth2/**",
                        "/login/**",
                        "/error",
                        "/v3/api-docs/**",
                        "/swagger-ui/**",
                        "/swagger-ui.html",
                        "/api/aegis/v1/auth/login",
                        "/api/aegis/v1/auth/register",
                        "/api/aegis/v1/auth/refresh",
                        "/api/aegis/v1/auth/logout",
                        "/api/aegis/v1/auth/link-account",
                        "/api/aegis/v1/auth/verify-email",
                        "/api/aegis/v1/auth/resend-verification",
                        "/api/aegis/v1/auth/mfa/verify",
                        "/api/aegis/v1/auth/mfa/recovery")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2Login(
            oauth2 ->
                oauth2
                    .loginPage("/oauth2/authorization/google")
                    .successHandler(oAuth2SuccessHandler)
                    .failureHandler(oAuth2FailureHandler))
        .oauth2ResourceServer(
            oauth2 ->
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
        .addFilterBefore(rateLimitingFilter, BearerTokenAuthenticationFilter.class)
        .addFilterAfter(tenantResolverFilter, BearerTokenAuthenticationFilter.class);

    return http.build();
  }
}
