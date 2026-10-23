# Aegis Sentinel Backend - Deployment & Operations Guide

This guide provides end-to-end instructions for running **Aegis Sentinel Backend** in Docker containers during development and deploying the production stack to a Linux server with Nginx, SSL, and automated health checks.

---

## 1. Local Development with Docker

### Prerequisites
- Docker Engine 24.x+
- Docker Compose v2.x+

### Quick Start (Full Stack Containerized)
To run the Spring Boot backend alongside PostgreSQL and Redis in Docker containers:

1. **Start infrastructure & application**:
   ```bash
   docker compose up -d --build
   ```

2. **Monitor logs**:
   ```bash
   docker compose logs -f aegis-backend
   ```

3. **Check container status**:
   ```bash
   docker compose ps
   ```

4. **Verify backend health**:
   ```bash
   curl http://localhost:8080/actuator/health
   ```

5. **Access Swagger UI API Docs**:
   Open [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html) in your browser.

6. **Stop services**:
   ```bash
   docker compose down -v
   ```

---

## 2. Production Server Deployment

### Architecture Overview
In production:
- **Nginx** handles public HTTP (80) and HTTPS (443) traffic, SSL termination, rate limiting, and reverse proxies requests to the Spring Boot backend.
- **Aegis Backend** runs in a non-root container bound locally to `127.0.0.1:8080`.
- **PostgreSQL** and **Redis** run in isolated internal container networks without exposing database ports to the host network.

```
 Internet (Port 80/443) ---> Nginx Proxy Container ---> Backend Container (Port 8080)
                                                                 |
                                                     +-----------+-----------+
                                                     |                       |
                                                     v                       v
                                             PostgreSQL Container      Redis Container
```

---

### Step 1: Initial Server Provisioning (One-Time Setup)

On a fresh Linux server (Ubuntu 22.04 LTS recommended):

1. **Clone the repository**:
   ```bash
   sudo mkdir -p /opt/aegis-sentinel
   cd /opt/aegis-sentinel
   git clone <YOUR_GIT_REPO_URL> .
   ```

2. **Run server setup script**:
   ```bash
   sudo ./scripts/server-setup.sh
   ```
   *This script installs Docker, Docker Compose, sets up UFW firewall rules for ports 22, 80, and 443, and installs Certbot.*

---

### Step 2: Environment Configuration

1. **Create production `.env.production` file**:
   ```bash
   cp .env.production.example .env.production
   ```

2. **Edit secrets**:
   ```bash
   nano .env.production
   ```
   Ensure you configure strong values for:
   - `DOMAIN_NAME`: Your domain (e.g., `api.aegissentinel.io`)
   - `POSTGRES_DB` & `POSTGRES_PASSWORD`: Production database credentials
   - `REDIS_PASSWORD`: Redis authentication password
   - `AEGIS_JWT_SECRET`: Base64 key (at least 32 bytes)
   - `GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET`: OAuth2 keys

---

### Step 3: SSL Certificate Setup (Let's Encrypt / Certbot)

1. **Obtain SSL Certificate**:
   ```bash
   sudo certbot certonly --standalone -d api.aegissentinel.io
   ```

2. **Enable HTTPS in Nginx**:
   Edit `docker/nginx/conf.d/aegis.conf` and uncomment the HTTPS server block pointing to `/etc/letsencrypt/live/api.aegissentinel.io/`.

---

### Step 4: Deploying the Application Stack

Run the automated deployment script:
```bash
./scripts/deploy.sh
```

The script will:
1. Pull latest code.
2. Build optimized multi-stage Docker images (`Dockerfile`).
3. Launch container stack via `docker-compose.prod.yml`.
4. Run health check polling on `/actuator/health`.

---

## 3. Maintenance & Monitoring

### Viewing Logs
- Backend logs: `docker compose -f docker-compose.prod.yml logs -f aegis-backend`
- Database logs: `docker compose -f docker-compose.prod.yml logs -f postgres`
- Nginx access/error logs: `docker compose -f docker-compose.prod.yml logs -f nginx`

### Database Backups
To create an automated PostgreSQL dump:
```bash
docker exec -t aegis-postgres-prod pg_dump -U aegis_admin aegis_prod > /var/backups/aegis_$(date +%Y%m%d_%H%M%S).sql
```

### Zero-Downtime Rollback / Restart
```bash
docker compose -f docker-compose.prod.yml restart aegis-backend
```
