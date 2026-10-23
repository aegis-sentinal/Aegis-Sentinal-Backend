#!/usr/bin/env bash
# ==============================================================================
# Aegis Sentinel - Server Provisioning & Initial Setup Script (Ubuntu/Debian)
# ==============================================================================
set -euo pipefail

echo "============================================================"
echo " Aegis Sentinel Backend - Server Setup Initializer"
echo "============================================================"

# Ensure script is run as root or with sudo
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script with sudo or as root."
  exit 1
fi

echo "[1/5] Updating system packages..."
apt-get update -y && apt-get upgrade -y
apt-get install -y curl git ufw ca-certificates gnupg lsb-release certbot

echo "[2/5] Installing Docker & Docker Compose v2..."
if ! command -v docker &> /dev/null; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable docker
  systemctl start docker
  echo "Docker successfully installed."
else
  echo "Docker is already installed."
fi

echo "[3/5] Setting up UFW Firewall rules..."
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable
ufw status verbose

echo "[4/5] Creating application directories..."
mkdir -p /opt/aegis-sentinel
echo "App directory created at /opt/aegis-sentinel"

echo "[5/5] Server initialization completed!"
echo "Next step: Clone your Aegis-Sentinel-Backend repository into /opt/aegis-sentinel and configure .env.production."
echo "============================================================"
