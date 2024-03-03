package com.authentication.jwt.repository;

import com.authentication.jwt.enums.ERole;
import com.authentication.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, String> {
    Optional<Role> findByRole(ERole role);
}
