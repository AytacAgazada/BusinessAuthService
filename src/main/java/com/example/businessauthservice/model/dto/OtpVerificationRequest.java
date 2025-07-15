package com.example.businessauthservice.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OtpVerificationRequest {

    @NotBlank(message = "Identifier (username or email) cannot be blank")
    private String identifier;
    @NotBlank(message = "OTP code cannot be blank")
    private String otpCode;
    @NotBlank(message = "OTP type cannot be blank")
    private String otpType;
}
