package com.aegis.identity.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.aegis.identity.api.dto.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
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

@SpringBootTest
class AuthControllerSliceTest {

  @Autowired private WebApplicationContext context;

  private final ObjectMapper objectMapper = new ObjectMapper();
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  @DisplayName(
      "Controller Test: /api/aegis/v1/auth/register creates organization and returns 201 CREATED with pending status")
  void testRegisterEndpoint_returnsPendingStatus() throws Exception {
    String unique = UUID.randomUUID().toString();
    RegisterRequest req =
        new RegisterRequest(
            "Controller Org " + unique,
            "ctrl-org-" + unique,
            "Controller Workspace",
            "ctrl-ws-" + unique,
            "ctrl-" + unique + "@aegis.test",
            "Password123!",
            "Ctrl",
            "User");

    MvcResult result =
        mockMvc
            .perform(
                post("/api/aegis/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isCreated())
            .andReturn();

    assertThat(result.getResponse().getContentAsString()).contains("EMAIL_VERIFICATION_REQUIRED");
    assertThat(result.getResponse().getContentAsString()).contains("verify your account");
  }
}
