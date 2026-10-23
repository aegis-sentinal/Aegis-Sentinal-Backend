-- Aegis Sentinel
-- V4: Detection Engine, Rules, Alerts & Telemetry Ingestion Schema

-- 1. Detection Rules Table
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    cloud_provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    query_pattern TEXT NOT NULL,
    mitre_attack_id VARCHAR(50),
    mitre_tactic VARCHAR(100),
    risk_score INTEGER NOT NULL DEFAULT 50,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_detection_rules_enabled ON detection_rules(is_enabled);
CREATE INDEX idx_detection_rules_provider ON detection_rules(cloud_provider);
CREATE INDEX idx_detection_rules_severity ON detection_rules(severity);

-- 2. Alerts Table
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    risk_score INTEGER NOT NULL DEFAULT 50,
    cloud_provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    affected_services TEXT,
    recommendation TEXT,
    retry_attempts INTEGER NOT NULL DEFAULT 0,
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alerts_org_ws ON alerts(organization_id, workspace_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_resource ON alerts(resource_id);

-- 3. Telemetry Ingestion Events Table
CREATE TABLE telemetry_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    event_id VARCHAR(255),
    event_source VARCHAR(100) NOT NULL,
    event_name VARCHAR(100) NOT NULL,
    principal_id VARCHAR(255),
    source_ip VARCHAR(45),
    destination_resource VARCHAR(255),
    cloud_provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    raw_payload TEXT,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    matched_rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_telemetry_org_ws ON telemetry_events(organization_id, workspace_id);
CREATE INDEX idx_telemetry_timestamp ON telemetry_events(timestamp DESC);
CREATE INDEX idx_telemetry_event_name ON telemetry_events(event_name);

-- 4. Seed Canonical AWS Detection Rules
INSERT INTO detection_rules (id, name, description, rule_type, severity, cloud_provider, query_pattern, mitre_attack_id, mitre_tactic, risk_score) VALUES
    ('20000000-0000-0000-0000-000000000001',
     'AWS Root Account Console Login Without MFA',
     'Detects console login activities using the AWS root account without multi-factor authentication.',
     'SIGMA',
     'critical',
     'aws',
     'eventName:ConsoleLogin AND userIdentity.type:Root AND additionalEventData.MFAUsed:No',
     'T1078.004',
     'Initial Access',
     95),

    ('20000000-0000-0000-0000-000000000002',
     'Unauthorized IAM Access Key Generation',
     'Detects generation of permanent IAM credentials outside standard administrative workflows.',
     'SIGMA',
     'high',
     'aws',
     'eventName:CreateAccessKey',
     'T1098.001',
     'Persistence',
     80),

    ('20000000-0000-0000-0000-000000000003',
     'Sensitive S3 Bucket ACL or Policy Made Public',
     'Flags changes to S3 bucket access control lists or bucket policies granting public access.',
     'SIGMA',
     'critical',
     'aws',
     'eventName:PutBucketAcl OR eventName:PutBucketPolicy',
     'T1530',
     'Exfiltration',
     92),

    ('20000000-0000-0000-0000-000000000004',
     'Security Group Ingress Permitted to 0.0.0.0/0 (SSH/RDP)',
     'Identifies security group rule updates permitting unrestricted ingress traffic on sensitive administration ports 22 or 3389.',
     'SIGMA',
     'high',
     'aws',
     'eventName:AuthorizeSecurityGroupIngress AND (requestParameters.ipPermissions.items.fromPort:22 OR requestParameters.ipPermissions.items.fromPort:3389)',
     'T1562.001',
     'Defense Evasion',
     85),

    ('20000000-0000-0000-0000-000000000005',
     'CloudTrail Logging Disabled or Deleted',
     'Detects attempts to stop, disable, or delete AWS CloudTrail audit logs.',
     'SIGMA',
     'critical',
     'aws',
     'eventName:StopLogging OR eventName:DeleteTrail',
     'T1562.008',
     'Defense Evasion',
     98);
