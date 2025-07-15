package com.example.businessauthservice.repository;

import com.example.businessauthservice.model.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<Otp, Long> {

    Optional<Otp> findByIdentifierAndOtpTypeAndUsedFalseAndExpiryDateAfter(String identifier, String otpType, Instant now);

    Optional<Otp> findByIdentifierAndOtpType(String identifier, String otpType);
}