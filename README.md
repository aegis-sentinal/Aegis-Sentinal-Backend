# Aegis Sentinel Backend

> **Enterprise Cloud Incident Detection & Response (CIDR) Platform**
> Built with Java 21, Spring Boot 4, Spring Security 6, PostgreSQL 16, Redis, Apache Kafka, and OpenAPI 3.0.

---

## 🛡️ Project Overview

**Aegis Sentinel** is an enterprise-grade Cloud Incident Detection and Response (CIDR) platform designed for modern multi-tenant cloud environments. It provides real-time threat detection, automated incident investigation, intelligence threat feed integration, SOAR workflow playbooks, and AI-assisted security analysis.

The system is engineered using **Clean Architecture** and **Domain-Driven Design (DDD)** principles to enforce strict separation of concerns between core domain models, application use-cases, and infrastructure adapters.

---

## 📊 Master Development Roadmap & Progress Tracker

The platform is developed across distinct operational phases. **Phases 1 through 7 (Identity Subsystem & Developer Experience) are fully completed and verified.**

| Phase | Domain / Subsystem | Scope / Key Focus | Status |
| :--- | :--- | :--- | :---: |
| **Phase 1** | **Core Infrastructure** | Project bootstrap, Spring Boot 4, Docker Compose, Flyway, PostgreSQL, Redis, Kafka, Jacoco, Spotless, Checkstyle | ✅ Completed |
| **Phase 2** | **Identity Data Model** | Domain entities (User, UserIdentity, Organization, Workspace, Role, Permission, Session), Flyway migrations, JPA Repositories | ✅ Completed |
| **Phase 3** | **Authentication System** | Password hashing (BCrypt), JWT Access Tokens, Refresh Token rotation (SHA-256 database hashing), Org registration, Login, Refresh, Logout | ✅ Completed |
| **Phase 4** | **OAuth2 Federation** | Google OAuth2 integration, `OAuth2SuccessHandler`, `OAuth2FailureHandler`, Account linking (`/link-account`) | ✅ Completed |
| **Phase 5** | **Multi-Tenancy & RBAC** | Org & Workspace context scoping, `TenantResolverFilter`, `TenantContext`, `X-Organization-Id` & `X-Workspace-Id` headers, fine-grained `@PreAuthorize` permission evaluator | ✅ Completed |
| **Phase 6** | **Security Hardening & Audit** | Rate-limiting filter (`RateLimitingFilter`), OWASP security headers, `SecurityAuditLogger`, structured `SecurityAuditEvent` publisher | ✅ Completed |
| **Phase 7** | **API Specs & Dev Experience** | SpringDoc OpenAPI 3.0 setup, Swagger UI (`/swagger-ui.html`), `ApiErrorResponse` standardized error schema, Postman v2.1 collection, IntelliJ HTTP client, developer guide | ✅ Completed |
| **Phase 8** | **Detection Domain** | Real-time cloud log ingestion, detection rule engine, alert processing & correlation, Flyway V4 migration | ✅ Completed |
| **Phase 9** | **Investigation Domain** | Incident timeline construction, evidence graph, forensic artifact analysis, Flyway V5 migration | ✅ Completed |
| **Phase 10** | **Watchtower Domain** | Threat intelligence feed ingestion, IOC matching, vulnerability enrichment | 📅 Next |
| **Phase 11** | **Forge Domain** | SOAR automation playbooks, automated mitigation workflows, action triggers | 📅 Planned |
| **Phase 12** | **Oracle Domain** | AI security analyst assistant, natural language threat querying, incident summarization | 📅 Planned |
| **Phase 13** | **Platform Hardening & Release** | Production deployment, end-to-end performance benchmarking, final release | 📅 Planned |

---

## 🔑 Key Features Completed (Phases 1 – 7)

### 1. Multi-Tenant Organization & Workspace Scoping
- **Hierarchical Isolation**: `Organization` (Level 1 Tenant) $\rightarrow$ `Workspace` (Level 2 Sub-tenant).
- **Header Scoping**: Request context is injected via `X-Organization-Id` and `X-Workspace-Id` HTTP headers.
- **Thread-Local Context**: Enforced by [`TenantResolverFilter`](file:///home/sushant/Projects/btech_project/Aegis-Sentinel-Backend/src/main/java/com/aegis/identity/infrastructure/security/tenant/TenantResolverFilter.java) and managed in [`TenantContext`](file:///home/sushant/Projects/btech_project/Aegis-Sentinel-Backend/src/main/java/com/aegis/identity/infrastructure/security/tenant/TenantContext.java).

### 2. Dual-Token Authentication & Token Rotation
- **Access Tokens**: Short-lived JWTs (15 min TTL) signed with HMAC-SHA256 containing user identity, active tenant IDs, assigned roles, and granted permissions.
- **Refresh Tokens**: Long-lived tokens (7 days TTL). To protect against database breach token misuse, refresh tokens are stored as **SHA-256 cryptographically hashed strings** (`Sha256RefreshTokenHasher`).
- **Token Rotation**: Every call to `/api/aegis/v1/auth/refresh` revokes the previous refresh token and issues a new access/refresh pair.

### 3. Federated OAuth2 & Account Linking
- **Google OAuth2 Support**: Integrated via Spring Security OAuth2 Client with custom success/failure handlers ([`OAuth2SuccessHandler`](file:///home/sushant/Projects/btech_project/Aegis-Sentinel-Backend/src/main/java/com/aegis/identity/infrastructure/security/oauth/OAuth2SuccessHandler.java)).
- **Account Linking**: The `/api/aegis/v1/auth/link-account` endpoint allows users to link third-party provider identity subjects (e.g. Google sub) to an existing password account.

### 4. Fine-Grained RBAC & Tenant Security Evaluator
- **Role-Based Access**: Pre-defined system roles (`ROLE_ORG_ADMIN`, `ROLE_WORKSPACE_ADMIN`, `ROLE_ANALYST`).
- **Permission Authorities**: Fine-grained permissions (e.g., `alert:read`, `alert:write`, `workflow:execute`, `system:super-admin`).
- **Declarative Expression Security**: Powered by Spring Method Security `@PreAuthorize("@tenantSecurity.hasPermission(#orgId, 'alert:read')")` to ensure cross-tenant data leakage is impossible.

### 5. Abuse Prevention & Security Audit Trail
- **Rate Limiting**: Custom `RateLimitingFilter` prevents brute-force login and API flooding.
- **Security Headers**: Enforces `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Permissions-Policy`.
- **Security Audit Logger**: Publishes structured `SecurityAuditEvent` events for registration, authentication, token rotation, logout, and access denials.

### 6. Interactive OpenAPI Documentation & Standardized Errors
- **SpringDoc OpenAPI 3.0**: Exposes interactive Swagger UI at `/swagger-ui.html` and OpenAPI specification at `/v3/api-docs`.
- **Standard Error Schema**: All exceptions are translated by [`GlobalExceptionHandler`](file:///home/sushant/Projects/btech_project/Aegis-Sentinel-Backend/src/main/java/com/aegis/identity/exception/GlobalExceptionHandler.java) into a uniform [`ApiErrorResponse`](file:///home/sushant/Projects/btech_project/Aegis-Sentinel-Backend/src/main/java/com/aegis/identity/api/dto/ApiErrorResponse.java) payload containing HTTP status, error message, URI path, ISO timestamp, and field-level validation maps.

---

## 🌐 API Endpoint Reference Table

All endpoints are versioned under the `/api/aegis/v1` base URI.

| HTTP Method | Endpoint Path | Description | Auth Required | Scoping Headers / Security |
| :--- | :--- | :--- | :---: | :--- |
| `POST` | `/api/aegis/v1/auth/register` | Register organization, workspace, & admin user | ❌ Public | Creates initial tenant context |
| `POST` | `/api/aegis/v1/auth/login` | Authenticate password credentials | ❌ Public | Returns JWT Access & Refresh tokens |
| `POST` | `/api/aegis/v1/auth/refresh` | Exchange refresh token for new access token | ❌ Public | Rotates refresh token |
| `POST` | `/api/aegis/v1/auth/logout` | Revoke active user session & refresh token | ❌ Public | Invalidates database session |
| `POST` | `/api/aegis/v1/auth/link-account` | Link OAuth provider subject to account | ❌ Public | Validates user password & provider subject |
| `GET` | `/api/aegis/v1/auth/me` | Fetch active user profile & tenant context | ✅ Bearer JWT | Returns user, org, workspace, roles & permissions |
| `GET` | `/api/aegis/v1/rbac-test/alert-read` | Verify `alert:read` permission | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `GET` | `/api/aegis/v1/rbac-test/workflow-execute` | Verify `workflow:execute` permission | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('workflow:execute')")` |
| `GET` | `/api/aegis/v1/rbac-test/org-admin` | Verify `ORG_ADMIN` role | ✅ Bearer JWT | `@PreAuthorize("hasRole('ORG_ADMIN')")` |
| `GET` | `/api/aegis/v1/rbac-test/orgs/{orgId}/alerts` | Verify tenant organization alert access | ✅ Bearer JWT | `X-Organization-Id` |
| `GET` | `/api/aegis/v1/rbac-test/orgs/{orgId}/workspaces/{wsId}/alerts` | Verify tenant workspace alert access | ✅ Bearer JWT | `X-Organization-Id`, `X-Workspace-Id` |
| `GET` | `/api/aegis/v1/alerts` | Paginated list of security alerts with filtering | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `GET` | `/api/aegis/v1/alerts/{id}` | Get security alert details by ID | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `PATCH` | `/api/aegis/v1/alerts/{id}/status` | Update alert status & resolution notes | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:write')")` |
| `GET` | `/api/aegis/v1/alerts/metrics` | Retrieve aggregate posture metrics & MTTR | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `POST` | `/api/aegis/v1/telemetry/ingest` | Stream cloud telemetry event & trigger rules | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:write')")` |
| `GET` | `/api/aegis/v1/rules` | Retrieve list of active Sigma detection rules | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `GET` | `/api/aegis/v1/incidents` | Paginated security incidents with severity/status filtering | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `GET` | `/api/aegis/v1/incidents/{id}` | Full incident dossier, attack timeline, & evidence graph | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:read')")` |
| `PATCH` | `/api/aegis/v1/incidents/{id}/status` | Transition incident lifecycle (new, investigating, resolved) | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:write')")` |
| `POST` | `/api/aegis/v1/incidents/{id}/comments` | Add analyst annotation comment and timeline entry | ✅ Bearer JWT | `@PreAuthorize("hasAuthority('alert:write')")` |

---

## 📂 Project Architecture & Package Structure

```
Aegis-Sentinel-Backend/
├── config/
│   └── checkstyle/          # Checkstyle XML rule configuration
├── docs/
│   ├── postman/             # Postman v2.1 export collection
│   ├── aegis-sentinel.http  # IntelliJ / VS Code REST client test script
│   ├── developer-setup.md   # Complete local developer onboarding guide
│   └── api-architecture.md  # System architecture & design specification
├── src/
│   ├── main/
│   │   ├── java/com/aegis/identity/
│   │   │   ├── api/          # REST Controllers, DTO records, OpenAPI annotations
│   │   │   ├── application/  # Application services, CQRS commands, queries
│   │   │   ├── domain/       # Core Domain entities, value objects, domain events
│   │   │   ├── exception/    # GlobalExceptionHandler & ApiErrorResponse
│   │   │   └── infrastructure/# Persistence JPA adapters, Security, JWT, OAuth2, Tenant filters
│   │   └── resources/
│   │       ├── db/migration/ # Flyway database schema migrations (V1..V4)
│   │       └── application.yml# Spring Boot configuration
│   └── test/                 # Slice, integration, & security test suites
├── build.gradle.kts          # Gradle build configuration with Spring Boot 4
├── docker-compose.yml        # Infrastructure container dependencies
└── README.md
```

---

## 🛠️ Developer Setup & Quickstart Guide

### 1. Prerequisites
Ensure you have the following installed on your host machine:
- **Java 21 JDK** (Eclipse Temurin or Amazon Corretto)
- **Docker** and **Docker Compose**
- **Git**

### 2. Environment Configuration
Copy `.env.example` or configure environment variables in `.env`:

```env
SPRING_PROFILES_ACTIVE=dev
AEGIS_JWT_SECRET=dGhpcy1pcy1hLXZlcnktc2VjdXJlLWRldmVsb3BtZW50LWp3dC1zZWNyZXQta2V5LTMyLWJ5dGVzLW1pbg==
GOOGLE_CLIENT_ID=google-client-id-placeholder.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=google-client-secret-placeholder
```

### 3. Launch Infrastructure Services
Start PostgreSQL, Redis, and Apache Kafka containers:

```bash
docker compose up -d
```

### 4. Run the Backend Application
Start the Spring Boot backend server locally:

```bash
./gradlew bootRun
```
The backend server will run at `http://localhost:8080`.

### 5. Access Interactive OpenAPI Documentation
- **Swagger UI**: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)
- **OpenAPI JSON Spec**: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)

---

## 🧪 Testing & Code Quality Commands

### Execute Automated Test Suite
Runs all unit, slice, and security integration tests (including [`OpenApiIntegrationTest`](file:///home/sushant/Projects/btech_project/Aegis-Sentinel-Backend/src/test/java/com/aegis/identity/api/OpenApiIntegrationTest.java)):

```bash
./gradlew test
```

### Code Style Formatting (Spotless)
Enforces Google Java Format across the codebase:

```bash
# Check format compliance
./gradlew spotlessCheck

# Apply formatting automatically
./gradlew spotlessApply
```

### Static Analysis (Checkstyle)
Runs static code analysis:

```bash
./gradlew checkstyleMain checkstyleTest
```

### Full Clean Build Verification
Runs clean compilation, tests, format checks, static analysis, and packages the executable JAR:

```bash
./gradlew clean test build
```

---

## 📄 Documentation Links

- 📖 [Developer Setup Guide](docs/developer-setup.md)
- 🏗️ [API Architecture & Design Specification](docs/api-architecture.md)
- 🚀 [Postman v2.1 Collection](docs/postman/aegis-sentinel-v1.postman_collection.json)
- ⚡ [HTTP Client Test Suite](docs/aegis-sentinel.http)
