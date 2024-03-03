package com.authentication.jwt.controller;

import com.authentication.jwt.model.Role;
import com.authentication.jwt.model.User;
import com.authentication.jwt.repository.RoleRepository;
import com.authentication.jwt.repository.UserRepository;
import com.authentication.jwt.enums.ERole;
import com.authentication.jwt.dto.request.LoginRequestDto;
import com.authentication.jwt.dto.request.RegisterRequestDto;
import com.authentication.jwt.dto.response.TokenResponseDto;
import com.authentication.jwt.dto.response.MessageResponseDto;
import com.authentication.jwt.utils.JWTUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequestDto loginRequestDto) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        User user = (User) authentication.getPrincipal();
        List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        TokenResponseDto response = TokenResponseDto.builder()
                .token(jwt)
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(roles)
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequestDto registerRequestDto) {
        if (userRepository.existsByUsername(registerRequestDto.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponseDto("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(registerRequestDto.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponseDto("Error: Email is already in use!"));
        }

        User user = new User(registerRequestDto.getUsername(), passwordEncoder.encode(registerRequestDto.getPassword()), registerRequestDto.getEmail());

        Set<String> strRoles = registerRequestDto.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByRole(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByRole(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByRole(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByRole(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponseDto("User registered successfully!"));
    }
}
