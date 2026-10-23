package com.aegis.intelligence.api.controller;

import com.aegis.identity.api.dto.ApiErrorResponse;
import com.aegis.intelligence.api.dto.MitreTechniqueStatResponse;
import com.aegis.intelligence.api.dto.ThreatIndicatorResponse;
import com.aegis.intelligence.api.dto.ThreatLookupRequest;
import com.aegis.intelligence.api.dto.ThreatLookupResponse;
import com.aegis.intelligence.application.service.ThreatFeedIngestionService;
import com.aegis.intelligence.application.service.ThreatIntelService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(
    name = "Intelligence & Watchtower",
    description =
        "Curated IoC reputation feeds, MITRE ATT&CK technique mapping, and external threat enrichment")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/aegis/v1/intelligence")
@RequiredArgsConstructor
public class ThreatIntelController {

  private final ThreatIntelService threatIntelService;
  private final ThreatFeedIngestionService feedIngestionService;

  @Operation(
      summary = "Query threat intelligence feeds",
      description =
          "Retrieves curated threat intelligence indicators matching search filters and severity.")
  @ApiResponses(
      value = {
        @ApiResponse(responseCode = "200", description = "Feed items retrieved"),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(
            responseCode = "403",
            description = "Forbidden",
            content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
      })
  @GetMapping("/feed")
  @PreAuthorize("hasAuthority('alert:read')")
  public Page<ThreatIndicatorResponse> getThreatFeed(
      @Parameter(description = "Page number (0-based)") @RequestParam(defaultValue = "0") int page,
      @Parameter(description = "Page size limit") @RequestParam(defaultValue = "20") int limit,
      @Parameter(description = "Keyword search on indicator or description")
          @RequestParam(required = false)
          String search,
      @Parameter(description = "Indicator type filter (e.g. IP_REPUTATION, CVE_EXPLOIT)")
          @RequestParam(required = false)
          String type,
      @Parameter(description = "Severity filter (CRITICAL, HIGH, MEDIUM, LOW)")
          @RequestParam(required = false)
          String severity) {

    Pageable pageable = PageRequest.of(page, limit, Sort.by(Sort.Direction.DESC, "lastSeen"));
    return threatIntelService.getFeed(search, type, severity, pageable);
  }

  @Operation(
      summary = "Enrich and lookup IoC indicator",
      description =
          "Queries threat intelligence repositories and reputation heuristics for an IP, domain, or hash.")
  @PostMapping("/lookup")
  @PreAuthorize("hasAuthority('alert:read')")
  public ThreatLookupResponse lookupIndicator(@Valid @RequestBody ThreatLookupRequest request) {
    return threatIntelService.lookup(request.indicator());
  }

  @Operation(
      summary = "Get MITRE ATT&CK technique statistics",
      description = "Retrieves active adversary techniques and detection frequencies.")
  @GetMapping("/mitre")
  @PreAuthorize("hasAuthority('alert:read')")
  public List<MitreTechniqueStatResponse> getMitreStatistics() {
    return threatIntelService.getMitreStats();
  }

  @Operation(
      summary = "Synchronize OSINT threat feeds",
      description = "Synchronizes indicators from CISA KEV, AlienVault OTX, and Tor exit nodes.")
  @PostMapping("/sync")
  @PreAuthorize("hasAuthority('alert:write')")
  public ThreatFeedIngestionService.FeedSyncResult syncThreatFeeds() {
    return feedIngestionService.syncFeeds();
  }
}
