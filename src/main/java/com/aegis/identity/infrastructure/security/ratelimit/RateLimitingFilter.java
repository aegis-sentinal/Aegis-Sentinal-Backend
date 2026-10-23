package com.aegis.identity.infrastructure.security.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

  private final int maxRequestsPerMinute;
  private final ObjectMapper objectMapper = new ObjectMapper();

  private final ConcurrentHashMap<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();

  public RateLimitingFilter(
      @Value("${aegis.security.rate-limit.auth-per-minute:1000}") int maxRequestsPerMinute) {
    this.maxRequestsPerMinute = maxRequestsPerMinute;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String path = request.getRequestURI();

    if (isRateLimitedPath(path)) {
      String clientIp = extractClientIp(request);
      RateLimitBucket bucket =
          buckets.compute(
              clientIp,
              (key, existing) -> {
                long now = System.currentTimeMillis();
                if (existing == null || now - existing.startTime > 60_000) {
                  return new RateLimitBucket(now, new AtomicInteger(1));
                }
                existing.count.incrementAndGet();
                return existing;
              });

      if (bucket.count.get() > maxRequestsPerMinute) {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Retry-After", "60");

        Map<String, Object> errorBody =
            Map.of(
                "error",
                "Too Many Requests",
                "message",
                "Rate limit exceeded. Please wait before trying again.",
                "status",
                429,
                "timestamp",
                Instant.now().toString());

        objectMapper.writeValue(response.getWriter(), errorBody);
        return;
      }
    }

    filterChain.doFilter(request, response);
  }

  private boolean isRateLimitedPath(String path) {
    return path.startsWith("/api/aegis/v1/auth/login")
        || path.startsWith("/api/aegis/v1/auth/register")
        || path.startsWith("/api/aegis/v1/auth/refresh")
        || path.startsWith("/api/aegis/v1/auth/link-account")
        || path.startsWith("/api/aegis/v1/auth/verify-email")
        || path.startsWith("/api/aegis/v1/auth/resend-verification")
        || path.startsWith("/api/aegis/v1/auth/mfa/verify")
        || path.startsWith("/api/aegis/v1/auth/mfa/recovery");
  }

  private String extractClientIp(HttpServletRequest request) {
    String xfHeader = request.getHeader("X-Forwarded-For");
    if (xfHeader == null || xfHeader.isBlank()) {
      return request.getRemoteAddr();
    }
    return xfHeader.split(",")[0].trim();
  }

  private static class RateLimitBucket {
    final long startTime;
    final AtomicInteger count;

    RateLimitBucket(long startTime, AtomicInteger count) {
      this.startTime = startTime;
      this.count = count;
    }
  }
}
