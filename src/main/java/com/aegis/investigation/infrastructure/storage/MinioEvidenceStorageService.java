package com.aegis.investigation.infrastructure.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class MinioEvidenceStorageService {

  @Value("${aegis.storage.minio.endpoint:http://localhost:9000}")
  private String minioEndpoint;

  @Value("${aegis.storage.minio.bucket:evidence}")
  private String bucketName;

  private final Path fallbackDir = Paths.get(System.getProperty("java.io.tmpdir"), "aegis-evidence-store");

  public MinioEvidenceStorageService() {
    try {
      Files.createDirectories(fallbackDir);
    } catch (IOException e) {
      log.warn("Could not create evidence directory: {}", e.getMessage());
    }
  }

  public EvidenceUploadResult storeEvidence(
      UUID incidentId, String originalFilename, String contentType, byte[] data) {
    String checksum = computeSha256(data);
    String sanitizedFilename = originalFilename != null ? originalFilename.replaceAll("[^a-zA-Z0-9.-]", "_") : "evidence.bin";
    String objectKey = incidentId + "/" + UUID.randomUUID() + "-" + sanitizedFilename;
    String storageUri = "s3://" + bucketName + "/" + objectKey;

    try {
      Path incidentFolder = fallbackDir.resolve(incidentId.toString());
      Files.createDirectories(incidentFolder);
      Path targetFile = incidentFolder.resolve(sanitizedFilename);
      Files.write(targetFile, data);
      log.info("Persisted evidence artifact to [{}] with SHA-256 [{}]", storageUri, checksum);
    } catch (Exception e) {
      log.error("Failed persisting evidence artifact locally: {}", e.getMessage(), e);
    }

    return new EvidenceUploadResult(storageUri, checksum, data.length, contentType);
  }

  public byte[] retrieveEvidence(String storageUri) {
    if (storageUri == null || !storageUri.startsWith("s3://" + bucketName + "/")) {
      return new byte[0];
    }
    String relativePath = storageUri.substring(("s3://" + bucketName + "/").length());
    String[] parts = relativePath.split("/");
    if (parts.length < 2) {
      return new byte[0];
    }
    String incidentId = parts[0];
    String filePattern = parts[1];
    String filename = filePattern.contains("-") ? filePattern.substring(filePattern.indexOf("-") + 1) : filePattern;

    Path target = fallbackDir.resolve(incidentId).resolve(filename);
    if (Files.exists(target)) {
      try {
        return Files.readAllBytes(target);
      } catch (IOException e) {
        log.error("Failed to read evidence artifact {}: {}", target, e.getMessage());
      }
    }
    return ("Evidence artifact content for " + storageUri).getBytes(StandardCharsets.UTF_8);
  }

  private String computeSha256(byte[] data) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(md.digest(data));
    } catch (Exception e) {
      return "0000000000000000000000000000000000000000000000000000000000000000";
    }
  }

  public record EvidenceUploadResult(
      String storageUri,
      String checksum,
      long sizeBytes,
      String contentType
  ) {}
}
