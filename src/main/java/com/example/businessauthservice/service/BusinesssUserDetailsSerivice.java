package com.example.businessauthservice.service;

import com.example.businessauthservice.repository.BusinnessUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Slf4j
@Service
@RequiredArgsConstructor
public class BusinesssUserDetailsSerivice implements UserDetailsService {

    private final BusinnessUserRepository businnessUserRepository;

    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        log.debug("Attempting to load user by identifier: {}", identifier);

        // 1. Username ilə axtarış
        var userOptByUserName = businnessUserRepository.findByUserName(identifier);
        if (userOptByUserName.isPresent()) {
            var user = userOptByUserName.get();
            log.info("User found by username: {}", user.getUserName());
            // UserDetails obyektini istifadəçinin username, password və rolu ilə qaytarır
            return new org.springframework.security.core.userdetails.User(
                    user.getUserName(),
                    user.getPassword(),
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRoles().name()))
            );
        }

        // 2. Email ilə axtarış (əgər username ilə tapılmayıbsa)
        var userOptByEmail = businnessUserRepository.findByEmail(identifier);
        if (userOptByEmail.isPresent()) {
            var user = userOptByEmail.get();
            log.info("User found by email: {}", user.getEmail());
            // Burada da UserDetails obyektini istifadəçinin username, password və rolu ilə qaytarır
            // Qeyd: loadUserByUsername metodu UserDetails obyektinin username-ini istifadə edir
            // buna görə də, email ilə tapılan istifadəçi üçün də user.getUserName() qaytarmaq düzgündür
            return new org.springframework.security.core.userdetails.User(
                    user.getUserName(),
                    user.getPassword(),
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRoles().name()))
            );
        }

        log.warn("User not found with identifier: {}", identifier);
        throw new UsernameNotFoundException("User not found with identifier: " + identifier);
    }
}