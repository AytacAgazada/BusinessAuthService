package com.example.businessauthservice.controller;

import com.example.businessauthservice.exception.ResourceNotFoundException;
import com.example.businessauthservice.model.dto.*;
import com.example.businessauthservice.repository.BusinnessUserRepository;
import com.example.businessauthservice.service.BusinessAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
@Slf4j
@Validated // MethodArgumentNotValidException GlobalExceptionHandler tərəfindən tutulacaq
public class BusinessAuthController {

    private final BusinessAuthService authService;
    private final BusinnessUserRepository businnessUserRepository;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody Signup signupRequest) {
        log.info("Signup request received for username: {}", signupRequest.getUserName());
        AuthResponse response = authService.signup(signupRequest);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody Login loginRequest) {
        log.info("Login request received for identifier: {}", loginRequest.getIdentifier());
        AuthResponse response = authService.login(loginRequest);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Refresh token request received for token: {}", request.getToken());
        AuthResponse response = authService.refreshToken(request);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/send-otp")
    public ResponseEntity<AuthResponse> sendOtp(@Valid @RequestBody OtpSendRequest request) {
        log.info("Send OTP request received for identifier: {} with type: {}", request.getIdentifier(), request.getOtpType());
        AuthResponse response = authService.sendOtp(request);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@Valid @RequestBody OtpVerificationRequest request) {
        log.info("Verify OTP request received for identifier: {} with type: {}", request.getIdentifier(), request.getOtpType());
        AuthResponse response = authService.verifyOtp(request);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<AuthResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        log.info("Password reset request received for identifier: {}", request.getIdentifier());
        AuthResponse response = authService.resetPassword(request);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()") // Yalnız daxil olmuş istifadəçilər üçün
    public ResponseEntity<AuthResponse> logout(Authentication authentication) {
        String username = authentication.getName();
        log.info("Logout request received for user: {}", username);
        AuthResponse response = authService.logout(username);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @DeleteMapping("/delete-account")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> deleteAccount(Authentication authentication) {
        String username = authentication.getName();
        authService.deleteAccount(username);
        return ResponseEntity.ok("Your account has been deleted successfully.");
    }


    // --- Demo endpoint for authenticated users (Optional) ---
    @GetMapping("/test-secured-owner")
    @PreAuthorize("hasRole('BUSINESS_OWNER')") // Bu annotasiya SecurityConfig-dəki requestMatchers-i əvəz edir
    public ResponseEntity<String> testSecuredOwnerEndpoint() {
        log.info("Accessing secured endpoint with BUSINESS_OWNER role.");
        return new ResponseEntity<>("You have accessed the BUSINESS_OWNER secured endpoint!", HttpStatus.OK);
    }

    // --- Demo endpoint for any authenticated user (Optional) ---
    @GetMapping("/test-secured-user")
    @PreAuthorize("isAuthenticated()") // Hər hansı daxil olmuş istifadəçi üçün
    public ResponseEntity<String> testSecuredUserEndpoint() {
        log.info("Accessing secured endpoint for any authenticated user.");
        return new ResponseEntity<>("You have accessed a secured endpoint as an authenticated user!", HttpStatus.OK);
    }

    @GetMapping("/{authUserId}/exists")
    public ResponseEntity<Boolean> doesUserExist(@PathVariable Long authUserId) {
        // businnessUserRepository-dən istifadə edərək bu ID-nin mövcudluğunu yoxlayırıq.
        boolean exists = businnessUserRepository.existsById(authUserId);
        return ResponseEntity.ok(exists);
    }

    @GetMapping("/{authUserId}/role")
    public ResponseEntity<String> getUserRole(@PathVariable Long authUserId) {
        log.info("Request to get role for authUserId: {}", authUserId);
        return businnessUserRepository.findById(authUserId)
                .map(authUser -> ResponseEntity.ok(authUser.getRoles().name()))
                .orElseThrow(() -> {
                    log.warn("Auth User with ID {} not found when checking role.", authUserId);
                    return new ResourceNotFoundException("Auth User with ID " + authUserId + " not found.");
                });
    }
}