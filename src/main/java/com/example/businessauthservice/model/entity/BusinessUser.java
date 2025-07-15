package com.example.businessauthservice.model.entity;

import com.example.businessauthservice.model.enumeration.Roles;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class BusinessUser{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50,unique = true)
    private String userName;

    @Column(unique = true, length = 100)
    private String email;

    @Column(nullable = false, length = 120)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Roles roles;

    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = false;

}