-- V7: Seed Initial Demo Organization and Admin User for Local Development & Integration Testing

INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000100', 'Aegis Sentinel Demo', 'aegis-demo')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO workspaces (id, organization_id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000200', '00000000-0000-0000-0000-000000000100', 'Production Enclave', 'production')
ON CONFLICT (organization_id, slug) DO NOTHING;

-- Admin user (password: StrongPassword123!)
INSERT INTO users (id, organization_id, email, password_hash, first_name, last_name, is_active, is_mfa_enabled)
VALUES (
    '00000000-0000-0000-0000-000000000300',
    '00000000-0000-0000-0000-000000000100',
    'admin@aegis-demo.local',
    '$2a$10$JTb9SV5wnSzfnAEhPLLPOecRXcfEzQnQefvmYUxt6z5urAXZTX0Rm',
    'Aegis',
    'Administrator',
    TRUE,
    FALSE
)
ON CONFLICT (email) DO NOTHING;

-- Assign ORG_ADMIN role to admin user scoped to production workspace
INSERT INTO user_roles (id, user_id, role_id, organization_id, workspace_id)
VALUES (
    '00000000-0000-0000-0000-000000000400',
    '00000000-0000-0000-0000-000000000300',
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000100',
    '00000000-0000-0000-0000-000000000200'
)
ON CONFLICT (user_id, role_id, organization_id, workspace_id) DO NOTHING;
