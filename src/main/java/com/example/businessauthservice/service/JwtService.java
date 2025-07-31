package com.example.businessauthservice.service;

import com.example.businessauthservice.model.entity.BusinessUser; // BusinessUser import edin
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j // Loğlama üçün
public class JwtService {

    // application.yml-dan secret key-i oxuyur
    @Value("${jwt.secret}")
    private String SECRET;

    // application.yml-dan Access Tokenin bitmə müddətini (milisaniyə ilə) oxuyur
    @Value("${jwt.expiration.ms}")
    private long jwtExpirationMs;


    /**
     * Tokenin içindən istifadəçi adını (subject) çıxarır.
     *
     * @param token İşlənəcək JWT token.
     * @return Tokenin subject (username) hissəsi.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Tokenin içindən bitmə tarixini çıxarır.
     *
     * @param token İşlənəcək JWT token.
     * @return Tokenin bitmə tarixi (Date obyekti).
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Tokenin içindən hər hansı bir claimi çıxarır.
     *
     * @param token İşlənəcək JWT token.
     * @param claimsResolver Claim-i çıxarmaq üçün funksiya (məsələn, Claims::getSubject).
     * @param <T> Claim-in tipi.
     * @return Çıxarılmış claim dəyəri.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Tokenin bütün claimlərini çıxarır. Bu metod daxili istifadə üçündür.
     *
     * @param token İşlənəcək JWT token.
     * @return Tokenin bütün claimləri (Claims obyekti).
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey()) // Tokenin imzasını doğrulamaq üçün gizli açar istifadə olunur
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Tokenin müddətinin bitib-bitmədiyini yoxlayır.
     *
     * @param token Yoxlanılacaq JWT token.
     * @return true əgər tokenin müddəti bitibsə, əks halda false.
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Tokenin etibarlılığını yoxlayır (username uyğunluğu və bitmə müddəti).
     *
     * @param token Yoxlanılacaq JWT token.
     * @param userDetails Autentifikasiya olunacaq istifadəçinin UserDetails obyekti.
     * @return true əgər token etibarlıdırsa, əks halda false.
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        // Tokenin içindəki username ilə UserDetails-dəki username-in uyğunluğunu və tokenin bitmədiyini yoxla
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * Yeni bir JWT Access Token yaradır.
     * Bu metod artıq BusinessUser obyekti qəbul edir.
     *
     * @param user Token yaradılacaq BusinessUser obyekti.
     * @return Yaradılmış JWT Access Token.
     */
    public String generateToken(com.example.businessauthservice.model.entity.BusinessUser user) { // <-- DƏYİŞİKLİK: BusinessUser qəbul edir
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRoles().name()); // Rolu "role" adlı bir claim olaraq tokenə əlavə edin
        claims.put("userId", user.getId()); // <-- ƏN VACİB DƏYİŞİKLİK: userId claim-ini əlavə edin!
        claims.put("email", user.getEmail()); // Email-i də əlavə etmək faydalı olar

        return createToken(claims, user.getUserName()); // username-i user obyektindən götürün
    }

    /**
     * Verilmiş claimlər və subject (istifadəçi adı) ilə token yaradır. Bu metod daxili istifadə üçündür.
     *
     * @param claims Tokendə saxlanılacaq əlavə məlumatlar.
     * @param userName Tokenin subject (istifadəçi adı).
     * @return Yaradılmış JWT token.
     */
    private String createToken(Map<String, Object> claims, String userName) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        // Access token üçün configuration-dan alınan müddəti istifadə et
        Date expiration = new Date(now + jwtExpirationMs);

        log.debug("Generating token for user: {}, role: {}, issued at: {}, expires at: {}", userName, claims.get("role"), issuedAt, expiration);

        return Jwts.builder()
                .setClaims(claims) // Custom claimləri əlavə et
                .setSubject(userName) // Tokenin subyekti (istifadəçi adı)
                .setIssuedAt(issuedAt) // Tokenin verilmə tarixi
                .setExpiration(expiration) // Tokenin bitmə tarixi
                .signWith(getSignKey(), SignatureAlgorithm.HS256) // Tokeni gizli açarla imzala
                .compact(); // JWT stringini yarat
    }


    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
