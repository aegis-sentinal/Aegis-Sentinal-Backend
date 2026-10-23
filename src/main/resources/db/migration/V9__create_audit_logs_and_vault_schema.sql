-- V9: Audit Logs & Security Compliance Schema for Immutable Audit Trails

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    result VARCHAR(50) NOT NULL DEFAULT 'SUCCESS',
    ip_address VARCHAR(45),
    details TEXT,
    digest_hash VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- Seed Canonical Audit Events
INSERT INTO audit_logs (organization_id, actor, action, resource, resource_type, result, ip_address, details, digest_hash) VALUES
    ('00000000-0000-0000-0000-000000000100', 'admin@aegis-demo.local', 'USER_LOGIN', 'auth-service', 'IDENTITY', 'SUCCESS', '198.51.100.12', 'MFA challenge verified with TOTP token', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    ('00000000-0000-0000-0000-000000000100', 'forge-engine', 'REMEDIATION_EXECUTE', 'sg-091f27c8230', 'AWS_SECURITY_GROUP', 'SUCCESS', '10.0.1.5', 'Revoked ingress port 8080 from 0.0.0.0/0', '8f9a2b4c5d6e7f1a3b5c8a901f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9012'),
    ('00000000-0000-0000-0000-000000000100', 'lead-analyst@aegis-demo.local', 'APPROVAL_GRANTED', 'wf-2026-081', 'SOAR_PLAYBOOK', 'SUCCESS', '192.168.1.105', 'Approved automated IAM key revocation', '7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f'),
    ('00000000-0000-0000-0000-000000000100', 'sentinel-core', 'RULE_EVALUATION', 'rule-aws-iam-01', 'DETECTION_RULE', 'SUCCESS', '10.0.2.20', 'Triggered alert ALT-2026-001 for suspicious AssumeRole', '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b'),
    ('00000000-0000-0000-0000-000000000100', 'prism-engine', 'INCIDENT_CREATED', 'inc-2026-001', 'INCIDENT', 'SUCCESS', '10.0.3.15', 'Clustered 3 correlated alerts into incident dossier', '1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c');
