# ==========================================
# Stage 1: Build Stage (Debian-based JDK for reliable DNS & Gradle downloads)
# ==========================================
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /app

# Copy gradle wrapper and build scripts first to leverage Docker layer caching
COPY gradle gradle
COPY gradlew settings.gradle.kts build.gradle.kts ./

# Make gradlew executable
RUN chmod +x gradlew

# Download dependencies (cache layer)
RUN ./gradlew dependencies --no-daemon || true

# Copy source code
COPY src src

# Build executable Spring Boot Jar without running tests (tests run in CI/CD pipeline)
RUN ./gradlew bootJar -x test --no-daemon

# ==========================================
# Stage 2: Runtime Stage
# ==========================================
FROM eclipse-temurin:21-jre-alpine AS runner

# Install curl for container health check
RUN apk add --no-cache curl tzdata

# Set timezone
ENV TZ=UTC

# Create dedicated non-root user and group
RUN addgroup -S aegisgroup && adduser -S aegisuser -G aegisgroup

WORKDIR /app

# Copy compiled jar from builder stage
COPY --from=builder --chown=aegisuser:aegisgroup /app/build/libs/*.jar app.jar

# Set container permissions
USER aegisuser:aegisgroup

# Expose backend service port
EXPOSE 8080

# Configure JVM tuning defaults for container environments
ENV JAVA_OPTS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:InitiatingHeapOccupancyPercent=45 -Djava.security.egd=file:/dev/./urandom"

# Healthcheck monitoring Spring Boot Actuator endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

# Launch Spring Boot Application
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
