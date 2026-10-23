package com.aegis.identity.application.service;

import com.aegis.identity.domain.entity.User;
import com.aegis.identity.domain.repository.UserRepository;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ResendEmailVerificationService {

  private final UserRepository userRepository;
  private final SendEmailVerificationService sendEmailVerificationService;

  public ResendEmailVerificationService(
      UserRepository userRepository, SendEmailVerificationService sendEmailVerificationService) {
    this.userRepository = userRepository;
    this.sendEmailVerificationService = sendEmailVerificationService;
  }

  @Transactional
  public void execute(String email) {
    Optional<User> userOpt = userRepository.findByEmail(email);

    if (userOpt.isPresent()) {
      User user = userOpt.get();
      if (!Boolean.TRUE.equals(user.getEmailVerified())) {
        sendEmailVerificationService.execute(user);
      }
    }
    // Note: If user does not exist or is already verified, do nothing to prevent account
    // enumeration
  }
}
