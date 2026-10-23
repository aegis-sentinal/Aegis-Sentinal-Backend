package com.aegis.detection.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum CloudProvider {
  AWS("aws"),
  AZURE("azure"),
  GCP("gcp"),
  MULTI_CLOUD("multi-cloud");

  private final String value;

  CloudProvider(String value) {
    this.value = value;
  }

  @JsonValue
  public String getValue() {
    return value;
  }

  @JsonCreator
  public static CloudProvider fromValue(String value) {
    if (value == null) {
      return AWS;
    }
    for (CloudProvider provider : values()) {
      if (provider.value.equalsIgnoreCase(value) || provider.name().equalsIgnoreCase(value)) {
        return provider;
      }
    }
    return AWS;
  }
}
