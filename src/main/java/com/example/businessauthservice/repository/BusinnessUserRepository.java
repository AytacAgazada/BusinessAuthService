package com.example.businessauthservice.repository;

import com.example.businessauthservice.model.entity.BusinessUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BusinnessUserRepository extends JpaRepository<BusinessUser,Long> {

    Optional<BusinessUser> findByUserName(String userName);
    Optional<BusinessUser> findByEmail(String email);

}
