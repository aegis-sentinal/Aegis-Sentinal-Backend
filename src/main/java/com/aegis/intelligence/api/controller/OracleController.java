package com.aegis.intelligence.api.controller;

import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.intelligence.api.dto.OracleChatRequest;
import com.aegis.intelligence.api.dto.OracleChatResponse;
import com.aegis.intelligence.application.service.OracleCopilotService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "AI Engine & Oracle",
    description =
        "Security copilot, LangGraph-aligned threat investigation, and automated triage reasoning")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/oracle")
@RequiredArgsConstructor
public class OracleController {

  private final OracleCopilotService oracleCopilotService;

  @Operation(
      summary = "Interact with Oracle AI Security Copilot",
      description =
          "Submits an analyst prompt or investigation context to the Oracle intelligence engine.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "AI investigation response generated"),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(
            responseCode = "403",
            description = "Forbidden",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @PostMapping("/chat")
  public OracleChatResponse chat(@Valid @RequestBody OracleChatRequest request) {
    return oracleCopilotService.chat(request);
  }
}
