-- Aegis Sentinel
-- V6: Automation Domain (Forge) - SOAR Playbooks, Approval Gates & Workflow Runs

-- 1. Playbooks Table
CREATE TABLE playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    action_type VARCHAR(50) NOT NULL,
    owasp_category VARCHAR(100),
    owasp_code VARCHAR(50),
    nist_phase VARCHAR(100),
    compliance_ref VARCHAR(100),
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_playbooks_enabled ON playbooks(is_enabled);
CREATE INDEX idx_playbooks_action ON playbooks(action_type);

-- 2. Workflow Runs Table
CREATE TABLE workflow_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'auto_remediation',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    target_resource VARCHAR(255) NOT NULL,
    executed_by VARCHAR(100) NOT NULL DEFAULT 'forge-engine',
    execution_log TEXT,
    result TEXT,
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_workflow_runs_org_ws ON workflow_runs(organization_id, workspace_id);
CREATE INDEX idx_workflow_runs_status ON workflow_runs(status);
CREATE INDEX idx_workflow_runs_alert ON workflow_runs(alert_id);
CREATE INDEX idx_workflow_runs_incident ON workflow_runs(incident_id);
CREATE INDEX idx_workflow_runs_executed_at ON workflow_runs(executed_at DESC);

-- 3. Workflow Approvals Table
CREATE TABLE workflow_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    decided_by UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_by_name VARCHAR(100),
    decision VARCHAR(20) NOT NULL,
    reason TEXT,
    decided_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_workflow_approvals_run ON workflow_approvals(workflow_run_id);

-- 4. Seed Canonical Forge Playbooks
INSERT INTO playbooks (id, name, description, action_type, owasp_category, owasp_code, nist_phase, compliance_ref, requires_approval) VALUES
    ('30000000-0000-0000-0000-000000000001',
     'Automated IAM User Access Key Revocation',
     'Deactivates and rotates exposed or compromised IAM access credentials across all cloud accounts.',
     'REVOKE_IAM_KEYS',
     'Broken Access Control',
     'A01:2021',
     'Mitigation (RS.MI)',
     'NIST SP 800-53 AC-2',
     TRUE),

    ('30000000-0000-0000-0000-000000000002',
     'Security Group Ingress Quarantine',
     'Revokes 0.0.0.0/0 ingress permissions on critical ports 22, 3389, and 8080.',
     'ISOLATE_SECURITY_GROUP',
     'Security Misconfiguration',
     'A05:2021',
     'Containment (RS.CO)',
     'CIS AWS Benchmark 4.1',
     TRUE),

    ('30000000-0000-0000-0000-000000000003',
     'Compromised EC2 Workload Quarantine',
     'Attaches quarantine security group, detaches public IP, and takes EBS forensic snapshot.',
     'QUARANTINE_EC2',
     'Identification and Authentication Failures',
     'A07:2021',
     'Containment (RS.CO)',
     'NIST SP 800-61 Rev. 2',
     TRUE),

    ('30000000-0000-0000-0000-000000000004',
     'S3 Bucket Public Access Block Enforcement',
     'Applies Amazon S3 Block Public Access settings and removes permissive public ACLs.',
     'BLOCK_IP',
     'Broken Access Control',
     'A01:2021',
     'Mitigation (RS.MI)',
     'SOC 2 CC6.1',
     TRUE);
