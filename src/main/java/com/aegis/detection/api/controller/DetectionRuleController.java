package com.aegis.detection.api.controller;

import com.aegis.detection.api.dto.DetectionRuleResponse;
import com.aegis.detection.application.service.DetectionRuleService;
import com.aegis.identity.api.dto.ApiErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Detection Rules",
    description =
        "Endpoints for managing Sentinel Core detection rules (Sigma, Behavioral, Heuristic)")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/rules")
@RequiredArgsConstructor
public class DetectionRuleController {

  private final DetectionRuleService detectionRuleService;

  @Operation(
      summary = "List active detection rules",
      description =
          "Retrieves all configured detection rules with MITRE ATT&CK mappings and severity levels.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Detection rules retrieved"),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping
  @PreAuthorize("hasAuthority('alert:read')")
  public List<DetectionRuleResponse> getRules() {
    return detectionRuleService.getAllRules();
  }
}
