package com.example.businessauthservice.model.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "otps") // Artıq uniqueConstraints yoxdur
public class Otp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // identifier unik olmasın, çünki bir user üçün bir neçə fərqli növ OTP ola bilər.
    @Column(nullable = false) // identifier artıq unique deyil
    private String identifier; // Email və ya Username (hansı ilə OTP göndərilibsə)

    @Column(nullable = false)
    private String otpCode;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private String otpType; // Məsələn: "ACCOUNT_CONFIRMATION", "PASSWORD_RESET"

    @Builder.Default
    @Column(nullable = false)
    private boolean used = false; // OTP istifadə edilibmi?
}