plugins {
    java

    id("org.springframework.boot") version "4.1.0"
    id("io.spring.dependency-management") version "1.1.7"

    jacoco
    checkstyle

    id("com.diffplug.spotless") version "7.2.1"
}

group = "com.aegis"
version = "0.1.0-SNAPSHOT"
description = "Enterprise Cloud Security Platform"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    implementation("org.springframework.boot:spring-boot-starter-kafka")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.flywaydb:flyway-database-postgresql")
    compileOnly("org.projectlombok:lombok")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    developmentOnly("org.springframework.boot:spring-boot-docker-compose")
    runtimeOnly("org.postgresql:postgresql")
    annotationProcessor("org.projectlombok:lombok")
    testImplementation("org.springframework.boot:spring-boot-starter-actuator-test")
    testImplementation("org.springframework.boot:spring-boot-starter-data-jpa-test")
    testImplementation("org.springframework.boot:spring-boot-starter-data-redis-test")
    testImplementation("org.springframework.boot:spring-boot-starter-flyway-test")
    testImplementation("org.springframework.boot:spring-boot-starter-kafka-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-test")
    testImplementation("org.springframework.boot:spring-boot-starter-validation-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.kafka:spring-kafka-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-postgresql")
    testImplementation("org.testcontainers:testcontainers-kafka")
    testCompileOnly("org.projectlombok:lombok")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testAnnotationProcessor("org.projectlombok:lombok")
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.9")
    implementation("org.apache.commons:commons-lang3:3.18.0")
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")
}

tasks.withType<Test> {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
    environment("AEGIS_JWT_SECRET", "dGhpcy1pcy1hLXZlcnktc2VjdXJlLWRldmVsb3BtZW50LWp3dC1zZWNyZXQta2V5LTMyLWJ5dGVzLW1pbg==")
    environment("GOOGLE_CLIENT_ID", "mock-google-client-id")
    environment("GOOGLE_CLIENT_SECRET", "mock-google-client-secret")
}

tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootRun") {
    val envFile = file(".env")
    if (envFile.exists()) {
        envFile.readLines().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isNotEmpty() && !trimmed.startsWith("#") && trimmed.contains("=")) {
                val parts = trimmed.split("=", limit = 2)
                val key = parts[0].trim()
                val value = parts[1].trim().removeSurrounding("\"").removeSurrounding("'")
                environment(key, value)
            }
        }
    }
    environment("AEGIS_JWT_SECRET", System.getenv("AEGIS_JWT_SECRET") ?: "dGhpcy1pcy1hLXZlcnktc2VjdXJlLWRldmVsb3BtZW50LWp3dC1zZWNyZXQta2V5LTMyLWJ5dGVzLW1pbg==")
    environment("GOOGLE_CLIENT_ID", System.getenv("GOOGLE_CLIENT_ID") ?: "mock-google-client-id")
    environment("GOOGLE_CLIENT_SECRET", System.getenv("GOOGLE_CLIENT_SECRET") ?: "mock-google-client-secret")
}

jacoco {
    toolVersion = "0.8.13"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

checkstyle {
    toolVersion = "10.26.1"
}

spotless {
    java {
        target("src/**/*.java")
        googleJavaFormat()
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
}

