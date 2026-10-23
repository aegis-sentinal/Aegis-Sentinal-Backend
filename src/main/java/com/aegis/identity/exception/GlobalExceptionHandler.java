package com.aegis.identity.exception;

import com.aegis.identity.api.dto.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ApiErrorResponse> handleIllegalArgument(
      IllegalArgumentException ex, HttpServletRequest request) {
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(
            HttpStatus.UNAUTHORIZED.value(), "Unauthorized", ex.getMessage(), path);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
  }

  @ExceptionHandler(IllegalStateException.class)
  public ResponseEntity<ApiErrorResponse> handleIllegalState(
      IllegalStateException ex, HttpServletRequest request) {
    HttpStatus status =
        ex.getMessage() != null && ex.getMessage().toLowerCase().contains("already linked")
            ? HttpStatus.CONFLICT
            : HttpStatus.BAD_REQUEST;
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(status.value(), status.getReasonPhrase(), ex.getMessage(), path);
    return ResponseEntity.status(status).body(body);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiErrorResponse> handleValidationExceptions(
      MethodArgumentNotValidException ex, HttpServletRequest request) {
    Map<String, String> fieldErrors = new HashMap<>();
    ex.getBindingResult()
        .getFieldErrors()
        .forEach(error -> fieldErrors.put(error.getField(), error.getDefaultMessage()));
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(
            HttpStatus.BAD_REQUEST.value(),
            "Bad Request",
            "Validation failed for request payload",
            path,
            fieldErrors);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
  }

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ApiErrorResponse> handleMalformedJson(
      HttpMessageNotReadableException ex, HttpServletRequest request) {
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(
            HttpStatus.BAD_REQUEST.value(), "Bad Request", "Malformed JSON request body", path);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
  }

  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ApiErrorResponse> handleConstraintViolation(
      ConstraintViolationException ex, HttpServletRequest request) {
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.getMessage(), path);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ApiErrorResponse> handleAccessDenied(
      AccessDeniedException ex, HttpServletRequest request) {
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(
            HttpStatus.FORBIDDEN.value(),
            "Forbidden",
            "Access denied: insufficient permissions or invalid tenant context",
            path);
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
  }

  @ExceptionHandler(com.aegis.common.exception.ResourceNotFoundException.class)
  public ResponseEntity<ApiErrorResponse> handleResourceNotFound(
      com.aegis.common.exception.ResourceNotFoundException ex, HttpServletRequest request) {
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(HttpStatus.NOT_FOUND.value(), "Not Found", ex.getMessage(), path);
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
  }

  @ExceptionHandler(com.aegis.common.exception.BadRequestException.class)
  public ResponseEntity<ApiErrorResponse> handleBadRequest(
      com.aegis.common.exception.BadRequestException ex, HttpServletRequest request) {
    String path = request != null ? request.getRequestURI() : null;
    ApiErrorResponse body =
        new ApiErrorResponse(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.getMessage(), path);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
  }
}
