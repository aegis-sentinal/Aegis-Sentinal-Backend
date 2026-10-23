-- V8: Threat Intelligence Domain (Watchtower) - Curated IoCs, MITRE ATT&CK Mapping & Threat Feeds

CREATE TABLE threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    indicator VARCHAR(255) NOT NULL UNIQUE,
    threat_description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    country VARCHAR(10),
    mitre_technique VARCHAR(50),
    confidence_score INTEGER NOT NULL DEFAULT 85,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_indicators_type ON threat_indicators(type);
CREATE INDEX idx_threat_indicators_severity ON threat_indicators(severity);
CREATE INDEX idx_threat_indicators_mitre ON threat_indicators(mitre_technique);
CREATE INDEX idx_threat_indicators_last_seen ON threat_indicators(last_seen DESC);

-- Seed Canonical Threat Feed Indicators
INSERT INTO threat_indicators (type, indicator, threat_description, severity, country, mitre_technique, confidence_score) VALUES
    ('IP_REPUTATION', '198.51.100.42', 'Known Tor Exit Node / Botnet Command Server', 'HIGH', 'RU', 'T1078', 92),
    ('CVE_EXPLOIT', 'CVE-2026-2819', 'AWS IAM Privilege Escalation exploit scan targeting AssumeRole API', 'CRITICAL', 'CN', 'T1098', 96),
    ('DOMAIN_THREAT', 'malicious-auth-portal.com', 'Phishing domain mimicking Okta enterprise SSO login portal', 'HIGH', 'UA', 'T1566', 90),
    ('MALWARE_HASH', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Ransomware loader binary payload targeting Linux cloud hosts', 'CRITICAL', 'KP', 'T1486', 99),
    ('IP_REPUTATION', '203.0.113.111', 'Active brute-force scan against SSH bastion grids', 'MEDIUM', 'NL', 'T1110', 82),
    ('PROXY_POOL', '185.220.101.5', 'Commercial proxy network scanning public S3 buckets for secrets', 'HIGH', 'DE', 'T1530', 88),
    ('CVE_EXPLOIT', 'CVE-2026-1049', 'Log4j variant RCE payload probe targeting Spring Boot API gateways', 'CRITICAL', 'CN', 'T1190', 98),
    ('K8S_EXPLOIT', '45.33.32.156', 'Unauthorized scanner executing Kubernetes API secret enumeration', 'MEDIUM', 'US', 'T1087', 79),
    ('C2_BEACON', '194.26.29.112', 'Cobalt Strike C2 beaconing IP address targeting cloud VPCs', 'CRITICAL', 'RU', 'T1071', 95),
    ('TYPOSQUAT_DOMAIN', 'bad-aws-console-login.net', 'Typosquatted domain capturing AWS IAM console credentials', 'HIGH', 'IR', 'T1566', 91),
    ('CVE_EXPLOIT', 'CVE-2026-5012', 'GKE Container Escape SYS_ADMIN privilege escalation exploit', 'CRITICAL', 'US', 'T1611', 97),
    ('DDOS_BOTNET', '77.247.181.162', 'Mirai botnet node launching HTTP flood on Cloud WAF endpoints', 'HIGH', 'BR', 'T1498', 86),
    ('CRYPTOMINER_HASH', '91.240.118.170', 'XMRig cryptominer binary download source targeting EC2 instances', 'MEDIUM', 'PL', 'T1496', 84),
    ('CVE_EXPLOIT', 'CVE-2026-3391', 'Azure Key Vault unauthorized secret extraction vulnerability scan', 'CRITICAL', 'CN', 'T1555', 96),
    ('SUPPLY_CHAIN', 'b2890a8872f1092e01f28bc098521a00a9', 'Trojanized npm package artifact injecting backdoor into CI/CD', 'HIGH', 'US', 'T1195', 93);
