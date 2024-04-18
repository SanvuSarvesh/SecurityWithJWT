package com.example.SpringSecurityWithJWT.repository;

import com.example.SpringSecurityWithJWT.models.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserProfile,Integer> {

    Optional<UserProfile> findByEmail(String email);

}
