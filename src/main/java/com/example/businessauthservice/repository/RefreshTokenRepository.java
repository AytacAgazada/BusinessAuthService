package com.example.businessauthservice.repository;

import com.example.businessauthservice.model.entity.BusinessUser;
import com.example.businessauthservice.model.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUser(BusinessUser user); // BU ƏLAVƏ EDİLMƏLİDİR!
    void deleteByUser(BusinessUser user);
}