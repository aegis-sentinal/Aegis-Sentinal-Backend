package com.aegis.detection.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum AlertSeverity {
  CRITICAL("critical"),
  HIGH("high"),
  MEDIUM("medium"),
  LOW("low");

  private final String value;

  AlertSeverity(String value) {
    this.value = value;
  }

  @JsonValue
  public String getValue() {
    return value;
  }

  @JsonCreator
  public static AlertSeverity fromValue(String value) {
    if (value == null) {
      return MEDIUM;
    }
    for (AlertSeverity severity : values()) {
      if (severity.value.equalsIgnoreCase(value) || severity.name().equalsIgnoreCase(value)) {
        return severity;
      }
    }
    return MEDIUM;
  }
}
