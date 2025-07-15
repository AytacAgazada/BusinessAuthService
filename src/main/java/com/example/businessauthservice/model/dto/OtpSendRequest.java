package com.example.businessauthservice.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OtpSendRequest {
    @NotBlank(message = "Identifier (username or email) cannot be blank")
    private String identifier;
    @NotBlank(message = "Send method must be 'email' or 'phone'")
    private String sendMethod; // 'email'
    @NotBlank(message = "OTP type cannot be blank (e.g., ACCOUNT_CONFIRMATION, PASSWORD_RESET)")
    private String otpType; // ACCOUNT_CONFIRMATION, PASSWORD_RESET
}