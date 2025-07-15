package com.example.businessauthservice.service;

import com.example.businessauthservice.model.entity.BusinessUser;
import com.example.businessauthservice.model.entity.RefreshToken;
import com.example.businessauthservice.repository.BusinnessUserRepository;
import com.example.businessauthservice.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Tranzaksiya üçün

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final BusinnessUserRepository businnessUserRepository;

    @Value("${jwt.refresh-expiration.ms}") // application.yml-dən oxumaq üçün
    private long refreshTokenExpirationMs;

    @Transactional // Tranzaksiya əlavə edin ki, əməliyyat atomik olsun
    public RefreshToken createRefreshToken(String username) {
        BusinessUser user = businnessUserRepository.findByUserName(username)
                .orElseThrow(() -> new RuntimeException("User not found for refresh token creation: " + username));

        // Bu istifadəçi üçün mövcud Refresh Tokeni axtarın
        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);

        RefreshToken refreshToken;
        if (existingToken.isPresent()) {
            // Əgər mövcud token varsa, onu yeniləyin
            refreshToken = existingToken.get();
            refreshToken.setToken(UUID.randomUUID().toString()); // Yeni unikal token stringi
            refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs)); // Yeni bitmə tarixi
        } else {
            // Əgər mövcud token yoxdursa, yeni yaradın
            refreshToken = RefreshToken.builder()
                    .user(user)
                    .token(UUID.randomUUID().toString())
                    .expiryDate(Instant.now().plusMillis(refreshTokenExpirationMs))
                    .build();
        }
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Transactional // Tranzaksiya üçün
    public void deleteByUserId(Long userId) {
        BusinessUser user = businnessUserRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found for deletion of refresh tokens"));
        refreshTokenRepository.deleteByUser(user);
    }
}