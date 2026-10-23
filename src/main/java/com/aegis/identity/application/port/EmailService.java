package com.aegis.identity.application.port;

public interface EmailService {

  void sendVerificationEmail(String recipientEmail, String rawToken);
}
