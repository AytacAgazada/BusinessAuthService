package com.example.businessauthservice.service;

import com.example.businessauthservice.exception.OtpException;
import com.example.businessauthservice.exception.ResourceNotFoundException;
import com.example.businessauthservice.exception.UserAlreadyExistsException;
import com.example.businessauthservice.model.dto.*;
import com.example.businessauthservice.model.entity.BusinessUser;
import com.example.businessauthservice.model.entity.Otp;
import com.example.businessauthservice.model.entity.RefreshToken;
import com.example.businessauthservice.model.enumeration.Roles;
import com.example.businessauthservice.repository.BusinnessUserRepository;
import com.example.businessauthservice.repository.OtpRepository;
import com.example.businessauthservice.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;

@Service
@RequiredArgsConstructor
@Slf4j
public class BusinessAuthService {

    private final BusinnessUserRepository businnessUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final OtpRepository otpRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    // --- Authentication and Authorization Flows ---

    @Transactional
    public AuthResponse signup(Signup signupRequest) {
        log.info("Attempting to sign up user: {}", signupRequest.getUserName());

        businnessUserRepository.findByUserName(signupRequest.getUserName())
                .ifPresent(user -> {
                    log.warn("Signup failed: Username '{}' already exists.", signupRequest.getUserName());
                    throw new UserAlreadyExistsException("Username '" + signupRequest.getUserName() + "' already exists.");
                });

        businnessUserRepository.findByEmail(signupRequest.getEmail())
                .ifPresent(user -> {
                    log.warn("Signup failed: Email '{}' already exists.", signupRequest.getEmail());
                    throw new UserAlreadyExistsException("Email '" + signupRequest.getEmail() + "' already exists.");
                });

        // Yeni əlavə olunan məntiq: Front-end-dən gələn rolu təyin etmək
        Roles assignedRole;
        try {
            assignedRole = Roles.valueOf(signupRequest.getSelectedRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Signup failed: Invalid role provided from frontend: {}", signupRequest.getSelectedRole());
            throw new IllegalArgumentException("Invalid role selected. Only 'USER' and 'BUSINESS_OWNER' are allowed.");
        }


        BusinessUser newUser = BusinessUser.builder()
                .userName(signupRequest.getUserName())
                .email(signupRequest.getEmail())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .roles(assignedRole) // Artıq front-end-dən gələn rolu təyin edirik
                .enabled(false) // Email təsdiqindən sonra aktiv olunacaq
                .build();

        BusinessUser savedUser = businnessUserRepository.save(newUser);
        log.info("User '{}' with role '{}' registered successfully. Sending account confirmation OTP.", savedUser.getUserName(), savedUser.getRoles().name());

        // Hesab təsdiqi üçün OTP göndərin
        OtpSendRequest otpSendRequest = new OtpSendRequest();
        otpSendRequest.setIdentifier(savedUser.getEmail()); // OTP-ni emailə göndəririk
        otpSendRequest.setSendMethod("email");
        otpSendRequest.setOtpType("ACCOUNT_CONFIRMATION");
        sendOtp(otpSendRequest); // OTP-ni göndərmək üçün metodunuzu çağırın

        return AuthResponse.builder()
                .username(savedUser.getUserName())
                .email(savedUser.getEmail())
                .role(savedUser.getRoles().name())
                .isAccountEnabled(savedUser.isEnabled())
                .message("User registered successfully. Please check your email for account confirmation OTP.")
                .build();
    }

    public AuthResponse login(Login loginRequest) {
        log.info("Attempting to log in user with identifier: {}", loginRequest.getIdentifier());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getIdentifier(), loginRequest.getPassword())
            );

            BusinessUser user = businnessUserRepository.findByUserName(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("Login failed: Authenticated user '{}' not found in database.", authentication.getName());
                        return new ResourceNotFoundException("Authenticated user not found.");
                    });

            if (!user.isEnabled()) {
                log.warn("Login failed for user '{}': Account is not enabled.", user.getUserName());
                throw new BadCredentialsException("Account is not enabled. Please confirm your email.");
            }

            String accessToken = jwtService.generateToken(user.getUserName(), user.getRoles());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUserName());
            log.info("User '{}' logged in successfully.", user.getUserName());

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .username(user.getUserName())
                    .email(user.getEmail())
                    .role(user.getRoles().name())
                    .isAccountEnabled(user.isEnabled())
                    .message("Login successful.") // Düzəliş edildi
                    .build();
        } catch (UsernameNotFoundException | BadCredentialsException e) {
            log.error("Authentication failed for identifier {}: {}", loginRequest.getIdentifier(), e.getMessage());
            throw e;
        }
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Attempting to refresh token: {}", request.getToken());

        RefreshToken refreshToken = refreshTokenService.findByToken(request.getToken())
                .orElseThrow(() -> {
                    log.warn("Refresh token failed: Token not found or invalid.");
                    return new ResourceNotFoundException("Refresh token not found or invalid.");
                });

        refreshTokenService.verifyExpiration(refreshToken);

        BusinessUser user = businnessUserRepository.findById(refreshToken.getUser().getId())
                .orElseThrow(() -> {
                    log.warn("Refresh token failed: User not found for token.");
                    return new ResourceNotFoundException("User not found for refresh token.");
                });

        String newAccessToken = jwtService.generateToken(user.getUserName(), user.getRoles());
        log.info("Access token refreshed successfully for user: {}", user.getUserName());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken.getToken()) // Refresh token eyni qalır
                .username(user.getUserName())
                .email(user.getEmail())
                .role(user.getRoles().name())
                .isAccountEnabled(user.isEnabled())
                .message("Access token refreshed successfully.") // Düzəliş edildi
                .build();
    }


    // --- OTP Related Flows ---

    @Transactional
    public AuthResponse sendOtp(OtpSendRequest request) {
        log.info("Attempting to send OTP to identifier: {} for type: {}", request.getIdentifier(), request.getOtpType());

        if (!"email".equalsIgnoreCase(request.getSendMethod())) {
            throw new OtpException("Only 'email' send method is currently supported.");
        }

        BusinessUser user = businnessUserRepository.findByEmail(request.getIdentifier())
                .orElseGet(() -> businnessUserRepository.findByUserName(request.getIdentifier())
                        .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + request.getIdentifier())));

        // Həmin identifier və OTP növü üçün aktiv, istifadə olunmamış OTP-ləri deaktiv edin
        otpRepository.findByIdentifierAndOtpTypeAndUsedFalseAndExpiryDateAfter(user.getEmail(), request.getOtpType(), Instant.now())
                .ifPresent(activeOtp -> {
                    activeOtp.setUsed(true); // Köhnə OTP-ni istifadə edilmiş kimi qeyd edin
                    otpRepository.save(activeOtp);
                    log.info("Deactivated previous active OTP for identifier: {} and type: {}", request.getIdentifier(), request.getOtpType());
                });

        String otpCode = generateRandomOtp(); // OTP kodu yaradın (məsələn, 6 rəqəmli)
        Instant expiryTime = Instant.now().plus(5, ChronoUnit.MINUTES); // 5 dəqiqə etibarlılıq müddəti

        Otp otp = Otp.builder()
                .identifier(user.getEmail()) // Emaili istifadə edin
                .otpCode(otpCode)
                .expiryDate(expiryTime)
                .otpType(request.getOtpType())
                .used(false)
                .build();
        otpRepository.save(otp);
        log.info("Generated new OTP for identifier: {} and type: {}", request.getIdentifier(), request.getOtpType());

        // Email göndərin
        String subject = "Your OTP for " + request.getOtpType().replace("_", " ").toLowerCase();
        String body = "Hello " + user.getUserName() + ",<br><br>"
                + "Your One-Time Password (OTP) for " + request.getOtpType().replace("_", " ").toLowerCase() + " is: <b>" + otpCode + "</b><br>"
                + "This OTP is valid for 5 minutes. Please do not share this code with anyone.<br><br>"
                + "Thank you.";
        emailService.sendEmail(user.getEmail(), subject, body); // Userin emailinə göndərin
        log.info("OTP email sent to: {}", user.getEmail());

        return AuthResponse.builder()
                .username(user.getUserName())
                .email(user.getEmail())
                .role(user.getRoles().name())
                .isAccountEnabled(user.isEnabled())
                .message("OTP sent successfully to " + user.getEmail()) // Düzəliş edildi
                .build();
    }

    @Transactional
    public AuthResponse verifyOtp(OtpVerificationRequest request) {
        log.info("Attempting to verify OTP for identifier: {} and type: {}", request.getIdentifier(), request.getOtpType());

        BusinessUser user = businnessUserRepository.findByEmail(request.getIdentifier())
                .orElseGet(() -> businnessUserRepository.findByUserName(request.getIdentifier())
                        .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + request.getIdentifier())));

        // Aktiv, istifadə olunmamış və müddəti keçməmiş OTP-ni tapın
        Otp otp = otpRepository.findByIdentifierAndOtpTypeAndUsedFalseAndExpiryDateAfter(user.getEmail(), request.getOtpType(), Instant.now())
                .orElseThrow(() -> {
                    log.warn("OTP verification failed: OTP not found, expired, or already used for identifier: {} and type: {}", request.getIdentifier(), request.getOtpType());
                    return new OtpException("Invalid, expired, or already used OTP.");
                });

        if (!otp.getOtpCode().equals(request.getOtpCode())) {
            log.warn("OTP verification failed: Incorrect OTP code for identifier: {} and type: {}", request.getIdentifier(), request.getOtpType());
            throw new OtpException("Incorrect OTP code.");
        }

        otp.setUsed(true); // OTP-ni istifadə edilmiş kimi qeyd edin
        otpRepository.save(otp);
        log.info("OTP successfully verified for identifier: {} and type: {}", request.getIdentifier(), request.getOtpType());

        String message = "OTP verified successfully.";
        Boolean isAccountEnabled = user.isEnabled(); // Başlanğıc vəziyyət

        if ("ACCOUNT_CONFIRMATION".equals(request.getOtpType())) {
            user.setEnabled(true); // Hesabı aktiv edin
            businnessUserRepository.save(user);
            isAccountEnabled = true; // Statusu güncəlləyin
            log.info("Account for user '{}' enabled successfully.", user.getUserName());
            message = "Account confirmed successfully.";
        } else if ("PASSWORD_RESET".equals(request.getOtpType())) {
            message = "OTP verified. You can now reset your password.";
        }

        return AuthResponse.builder()
                .username(user.getUserName())
                .email(user.getEmail())
                .role(user.getRoles().name())
                .isAccountEnabled(isAccountEnabled)
                .message(message) // Düzəliş edildi
                .build();
    }

    @Transactional
    public AuthResponse resetPassword(ResetPasswordRequest request) {
        log.info("Attempting to reset password for identifier: {}", request.getIdentifier());

        BusinessUser user = businnessUserRepository.findByEmail(request.getIdentifier())
                .orElseGet(() -> businnessUserRepository.findByUserName(request.getIdentifier())
                        .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + request.getIdentifier())));

        // Yeni şifrəni heşləyin
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        businnessUserRepository.save(user);
        log.info("Password for user '{}' reset successfully.", user.getUserName());

        // Şifrə sıfırlandıqdan sonra bütün köhnə refresh tokenlərini silin (təhlükəsizlik üçün)
        refreshTokenService.deleteByUserId(user.getId());
        log.info("All refresh tokens for user '{}' deleted after password reset.", user.getUserName());

        // İstifadəçi daxil olub yeni token ala bilər
        return AuthResponse.builder()
                .username(user.getUserName())
                .email(user.getEmail())
                .role(user.getRoles().name())
                .isAccountEnabled(user.isEnabled())
                .message("Password reset successfully. You can now login with your new password.") // Düzəliş edildi
                .build();
    }

    @Transactional
    public AuthResponse logout(String username) {
        log.info("Attempting to log out user: {}", username);

        BusinessUser user = businnessUserRepository.findByUserName(username)
                .orElseThrow(() -> {
                    log.warn("Logout failed: User '{}' not found.", username);
                    return new ResourceNotFoundException("User not found: " + username);
                });

        // İstifadəçiyə aid bütün refresh tokenlərini silin
        refreshTokenService.deleteByUserId(user.getId());
        log.info("All refresh tokens for user '{}' deleted successfully during logout.", username);

        return AuthResponse.builder()
                .message("User logged out successfully. All active sessions have been terminated.")
                .build();
    }


    // --- User Management (Optional: if needed in Auth Service) ---
    @Transactional
    public BusinessUser updateUserDetails(Long id, BusinessUser updatedUser) {
        log.info("Attempting to update user details for ID: {}", id);
        return businnessUserRepository.findById(id).map(existingUser -> {

            // Email və Username unikallığını yoxlayın
            if (!existingUser.getEmail().equals(updatedUser.getEmail())) {
                businnessUserRepository.findByEmail(updatedUser.getEmail())
                        .ifPresent(user -> {
                            log.warn("Update failed: Email '{}' already in use by another user for ID: {}.", updatedUser.getEmail(), id);
                            throw new UserAlreadyExistsException("Email '" + updatedUser.getEmail() + "' already in use by another user.");
                        });
                existingUser.setEmail(updatedUser.getEmail());
            }

            if (!existingUser.getUserName().equals(updatedUser.getUserName())) {
                businnessUserRepository.findByUserName(updatedUser.getUserName())
                        .ifPresent(user -> {
                            log.warn("Update failed: Username '{}' already in use by another user for ID: {}.", updatedUser.getUserName(), id);
                            throw new UserAlreadyExistsException("Username '" + updatedUser.getUserName() + "' already in use by another user.");
                        });
                existingUser.setUserName(updatedUser.getUserName());
            }

            if (updatedUser.getRoles() != null) {
                existingUser.setRoles(updatedUser.getRoles());
            }
            if (updatedUser.getPassword() != null && !updatedUser.getPassword().isBlank()) {
                existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
                log.info("Password updated for user ID: {}", id);
            }
            existingUser.setEnabled(updatedUser.isEnabled());


            businnessUserRepository.save(existingUser);
            log.info("User details updated successfully for ID: {}", id);
            return existingUser;
        }).orElseThrow(() -> {
            log.warn("User update failed: User not found with ID: {}", id);
            return new ResourceNotFoundException("User not found with ID: " + id);
        });
    }

    @Transactional
    public void deleteUser(Long id) {
        log.info("Attempting to delete user with ID: {}", id);
        if (!businnessUserRepository.existsById(id)) {
            log.warn("User deletion failed: User not found with ID: {}", id);
            throw new ResourceNotFoundException("User not found with ID: " + id);
        }
        refreshTokenService.deleteByUserId(id);
        businnessUserRepository.deleteById(id);
        log.info("User with ID: {} deleted successfully.", id);
    }

    public BusinessUser findUserById(Long id) {
        log.debug("Fetching user by ID: {}", id);
        return businnessUserRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));
    }

    public BusinessUser findUserByIdentifier(String identifier) {
        log.debug("Fetching user by identifier: {}", identifier);
        return businnessUserRepository.findByUserName(identifier)
                .or(() -> businnessUserRepository.findByEmail(identifier))
                .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + identifier));
    }

    @Transactional
    public void deleteAccount(String username) {
        BusinessUser user = businnessUserRepository.findByUserName(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        refreshTokenService.deleteByUserId(user.getId());
        businnessUserRepository.delete(user); // Silirik useri
        log.info("User '{}' deleted account successfully.", username);
    }


    // --- Utility Method for OTP generation ---

    private String generateRandomOtp() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000); // 6 rəqəmli OTP
        return String.valueOf(otp);
    }
}