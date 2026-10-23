package com.aegis.detection.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum AlertStatus {
  OPEN("open"),
  INVESTIGATING("investigating"),
  CONTAINED("contained"),
  RESOLVED("resolved"),
  FALSE_POSITIVE("false_positive");

  private final String value;

  AlertStatus(String value) {
    this.value = value;
  }

  @JsonValue
  public String getValue() {
    return value;
  }

  @JsonCreator
  public static AlertStatus fromValue(String value) {
    if (value == null) {
      return OPEN;
    }
    for (AlertStatus status : values()) {
      if (status.value.equalsIgnoreCase(value) || status.name().equalsIgnoreCase(value)) {
        return status;
      }
    }
    return OPEN;
  }
}
