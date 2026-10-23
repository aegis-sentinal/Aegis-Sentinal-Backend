package com.aegis.detection.domain.model;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class CloudProviderConverter implements AttributeConverter<CloudProvider, String> {

  @Override
  public String convertToDatabaseColumn(CloudProvider attribute) {
    if (attribute == null) {
      return null;
    }
    return attribute.getValue();
  }

  @Override
  public CloudProvider convertToEntityAttribute(String dbData) {
    if (dbData == null) {
      return null;
    }
    return CloudProvider.fromValue(dbData);
  }
}
