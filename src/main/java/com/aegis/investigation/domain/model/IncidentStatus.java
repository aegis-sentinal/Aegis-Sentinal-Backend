package com.aegis.investigation.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

public enum IncidentStatus {
  NEW("new"),
  INVESTIGATING("investigating"),
  ESCALATED("escalated"),
  REMEDIATION_PENDING("remediation_pending"),
  RESOLVED("resolved"),
  CLOSED("closed");

  private final String value;

  IncidentStatus(String value) {
    this.value = value;
  }

  @JsonValue
  public String getValue() {
    return value;
  }

  @JsonCreator
  public static IncidentStatus fromValue(String value) {
    if (value == null) {
      return NEW;
    }
    for (IncidentStatus status : values()) {
      if (status.value.equalsIgnoreCase(value) || status.name().equalsIgnoreCase(value)) {
        return status;
      }
    }
    return NEW;
  }

  @Converter(autoApply = true)
  public static class IncidentStatusConverter implements AttributeConverter<IncidentStatus, String> {
    @Override
    public String convertToDatabaseColumn(IncidentStatus attribute) {
      return attribute != null ? attribute.getValue() : null;
    }

    @Override
    public IncidentStatus convertToEntityAttribute(String dbData) {
      return dbData != null ? IncidentStatus.fromValue(dbData) : null;
    }
  }
}
