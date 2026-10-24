package com.aegis.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.aegis.identity.api.dto.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(
    properties = {
      "aegis.security.rate-limit.auth-per-minute=20",
      "management.health.redis.enabled=false"
    })
class ApiSecurityAndAbuseTest {

  @Autowired private WebApplicationContext context;

  private final ObjectMapper objectMapper = new ObjectMapper();
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  @DisplayName(
      "5.5 HTTP Security: Response headers must enforce frame options, content-type nosniff, referrer, and permissions policy")
  void testSecurityHeaders_presentInResponse() throws Exception {
    mockMvc
        .perform(get("/actuator/health"))
        .andExpect(status().isOk())
        .andExpect(header().string("X-Frame-Options", "DENY"))
        .andExpect(header().string("X-Content-Type-Options", "nosniff"))
        .andExpect(header().string("Referrer-Policy", "no-referrer"))
        .andExpect(
            header().string("Permissions-Policy", "geolocation=(), camera=(), microphone=()"));
  }

  @Test
  @DisplayName(
      "5.6 CORS: OPTIONS preflight request must return allowed origin, methods, and headers")
  void testCorsPreflightRequest_returnsAllowedOriginsAndMethods() throws Exception {
    mockMvc
        .perform(
            options("/api/aegis/v1/auth/login")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "Authorization, Content-Type"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
        .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
  }

  @Test
  @DisplayName(
      "5.7 Rate Limiting: Exceeding auth request limit from single IP returns 429 Too Many Requests with Retry-After header")
  void testRateLimiting_excessiveAuthRequests_returns429() throws Exception {
    String testIp = "192.168.1." + (int) (Math.random() * 200 + 10);
    LoginRequest req = new LoginRequest("ratelimit@aegis.test", "WrongPassword123!");

    // Send 20 requests (max per minute limit)
    for (int i = 0; i < 20; i++) {
      mockMvc
          .perform(
              post("/api/aegis/v1/auth/login")
                  .header("X-Forwarded-For", testIp)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(objectMapper.writeValueAsString(req)))
          .andExpect(status().isUnauthorized());
    }

    // 21st request should trigger 429
    MvcResult result =
        mockMvc
            .perform(
                post("/api/aegis/v1/auth/login")
                    .header("X-Forwarded-For", testIp)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "60"))
            .andReturn();

    assertThat(result.getResponse().getContentAsString()).contains("Rate limit exceeded");
  }

  @Test
  @DisplayName(
      "5.8 Input & Abuse: Malformed JSON payload returns 400 Bad Request with clean JSON error body")
  void testMalformedJsonRequest_returns400BadRequest() throws Exception {
    String invalidJson = "{ email: 'malformed_json_without_quotes', password: }";

    mockMvc
        .perform(
            post("/api/aegis/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidJson))
        .andExpect(status().isBadRequest());
  }
}
