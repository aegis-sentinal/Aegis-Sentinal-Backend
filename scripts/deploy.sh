#!/usr/bin/env bash
# ==============================================================================
# Aegis Sentinel - Automated Production Deployment Script
# ==============================================================================
set -euo pipefail

ENV_FILE=".env.production"
COMPOSE_FILE="docker-compose.prod.yml"

echo "============================================================"
echo " Aegis Sentinel Backend - Deployment Pipeline"
echo "============================================================"

# Step 1: Verify environment configuration
if [ ! -f "$ENV_FILE" ]; then
  echo "Error: Required environment file '$ENV_FILE' was not found!"
  echo "Please copy '.env.production.example' to '$ENV_FILE' and configure mandatory production secrets."
  exit 1
fi

echo "[1/4] Pulling latest code changes..."
git pull origin main || echo "Warning: git pull skipped or up to date."

echo "[2/4] Building and launching production container stack..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build --remove-orphans

echo "[3/4] Verifying container status..."
docker compose -f "$COMPOSE_FILE" ps

echo "[4/4] Performing health check on backend service..."
MAX_RETRIES=15
RETRY_COUNT=0
HEALTH_URL="http://127.0.0.1:8080/actuator/health"

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" || echo "000")
  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "SUCCESS: Aegis Sentinel Backend is UP and Healthy! (HTTP 200)"
    echo "============================================================"
    exit 0
  fi
  echo "Waiting for application startup... (Attempt $((RETRY_COUNT+1))/$MAX_RETRIES, Status: $HTTP_STATUS)"
  sleep 5
  RETRY_COUNT=$((RETRY_COUNT+1))
done

echo "ERROR: Health check failed after $MAX_RETRIES attempts."
echo "Fetching recent application container logs:"
docker compose -f "$COMPOSE_FILE" logs --tail 50 aegis-backend
exit 1
