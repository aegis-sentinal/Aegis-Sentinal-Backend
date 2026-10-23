package com.aegis.automation.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

public enum WorkflowRunStatus {
  PENDING("pending"),
  EXECUTED("executed"),
  FAILED("failed"),
  ROLLED_BACK("rolled_back");

  private final String value;

  WorkflowRunStatus(String value) {
    this.value = value;
  }

  @JsonValue
  public String getValue() {
    return value;
  }

  @JsonCreator
  public static WorkflowRunStatus fromValue(String value) {
    if (value == null) {
      return PENDING;
    }
    for (WorkflowRunStatus status : values()) {
      if (status.value.equalsIgnoreCase(value) || status.name().equalsIgnoreCase(value)) {
        return status;
      }
    }
    return PENDING;
  }

  @Converter(autoApply = true)
  public static class WorkflowRunStatusConverter
      implements AttributeConverter<WorkflowRunStatus, String> {
    @Override
    public String convertToDatabaseColumn(WorkflowRunStatus attribute) {
      return attribute != null ? attribute.getValue() : null;
    }

    @Override
    public WorkflowRunStatus convertToEntityAttribute(String dbData) {
      return dbData != null ? WorkflowRunStatus.fromValue(dbData) : null;
    }
  }
}
