package com.aegis.detection.domain.model;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class AlertSeverityConverter implements AttributeConverter<AlertSeverity, String> {

  @Override
  public String convertToDatabaseColumn(AlertSeverity attribute) {
    if (attribute == null) {
      return null;
    }
    return attribute.getValue();
  }

  @Override
  public AlertSeverity convertToEntityAttribute(String dbData) {
    if (dbData == null) {
      return null;
    }
    return AlertSeverity.fromValue(dbData);
  }
}
