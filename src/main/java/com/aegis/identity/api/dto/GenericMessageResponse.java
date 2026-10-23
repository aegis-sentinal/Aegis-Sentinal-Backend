package com.aegis.identity.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Generic success response message payload")
public record GenericMessageResponse(
    @Schema(description = "Message content", example = "Operation completed successfully")
        String message) {}
