package com.aegis.detection.domain.model;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class AlertStatusConverter implements AttributeConverter<AlertStatus, String> {

  @Override
  public String convertToDatabaseColumn(AlertStatus attribute) {
    if (attribute == null) {
      return null;
    }
    return attribute.getValue();
  }

  @Override
  public AlertStatus convertToEntityAttribute(String dbData) {
    if (dbData == null) {
      return null;
    }
    return AlertStatus.fromValue(dbData);
  }
}
