-- V10: Nexus Multi-Cloud Integrations & Third-Party Dispatch Schema

CREATE TABLE integration_connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_key VARCHAR(50) NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'INACTIVE',
    description TEXT NOT NULL,
    latency VARCHAR(50),
    last_sync TIMESTAMP WITH TIME ZONE,
    config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_connector_org_key UNIQUE (organization_id, connector_key)
);

CREATE INDEX idx_connectors_org ON integration_connectors(organization_id);
CREATE INDEX idx_connectors_category ON integration_connectors(category);
CREATE INDEX idx_connectors_status ON integration_connectors(status);

-- Seed Canonical Multi-Cloud & SOAR Integrations for Demo Org
INSERT INTO integration_connectors (organization_id, connector_key, name, category, status, description, latency, last_sync, config) VALUES
    ('00000000-0000-0000-0000-000000000100', 'aws', 'Amazon Web Services', 'CLOUD', 'CONNECTED', 'Ingests CloudTrail, GuardDuty, and VPC flow logs in real-time.', '120ms', CURRENT_TIMESTAMP - INTERVAL '10 seconds', '{"region":"us-east-1","accountId":"123456789012"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'gcp', 'Google Cloud Platform', 'CLOUD', 'CONNECTED', 'Streams audit events, Pub/Sub channels, and firewall telemetry.', '190ms', CURRENT_TIMESTAMP - INTERVAL '1 minute', '{"projectId":"aegis-sentinel-prod"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'azure', 'Microsoft Azure', 'CLOUD', 'INACTIVE', 'Polls Activity Logs, Security Center warnings, and Cosmos telemetry.', '250ms', NULL, '{"tenantId":"azure-aegis-demo"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'kubernetes', 'Kubernetes Cluster Fleet', 'CLOUD', 'CONNECTED', 'Monitors Kube-Audit events, daemonsets, and container runtime alerts.', '85ms', CURRENT_TIMESTAMP - INTERVAL '30 seconds', '{"cluster":"prod-us-central"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'slack', 'Slack Bot Dispatcher', 'ALERTING', 'CONNECTED', 'Dispatches high-priority alert cards to custom incident response channels.', '40ms', CURRENT_TIMESTAMP - INTERVAL '12 seconds', '{"channel":"#soc-critical-alerts"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'pagerduty', 'PagerDuty Escalation', 'ALERTING', 'PENDING', 'Creates service incidents and pages on-call engineers during critical outbreaks.', NULL, NULL, '{"serviceKey":"pd-secops-escalate"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'jira', 'Atlassian Jira', 'TICKETING', 'CONNECTED', 'Generates tracking tickets in SecOps project queues for new security incidents.', '340ms', CURRENT_TIMESTAMP - INTERVAL '5 minutes', '{"projectKey":"SECOPS"}'::jsonb),
    ('00000000-0000-0000-0000-000000000100', 'splunk', 'Splunk HEC Node', 'SIEM', 'INACTIVE', 'Forwards resolved security events and timeline digests to Splunk indexers.', NULL, NULL, '{"endpoint":"https://hec.splunk.internal:8088"}'::jsonb);
