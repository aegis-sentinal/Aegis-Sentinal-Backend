package com.aegis.automation.domain.model;

public enum ActionType {
  REVOKE_IAM_KEYS,
  ISOLATE_SECURITY_GROUP,
  QUARANTINE_EC2,
  BLOCK_IP,
  BLOCK_S3_PUBLIC,
  QUARANTINE_K8S_POD
}
