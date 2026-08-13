package com.alberto.tfm.vulnerabilidades.controller;

import com.alberto.tfm.vulnerabilidades.dto.AuthResponse;
import com.alberto.tfm.vulnerabilidades.dto.AvailabilityResponse;
import com.alberto.tfm.vulnerabilidades.dto.LoginRequest;
import com.alberto.tfm.vulnerabilidades.dto.RegisterRequest;
import com.alberto.tfm.vulnerabilidades.models.User;
import com.alberto.tfm.vulnerabilidades.repository.UserRepository;
import com.alberto.tfm.vulnerabilidades.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);

            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
            session.setMaxInactiveInterval(86400); // 24 hours

            User user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

            log.info("User {} logged in with role {}", loginRequest.getUsername(), user.getRole());
            return ResponseEntity.ok(AuthResponse.success(user));
        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for {}", loginRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.failure("Usuario o contraseña incorrectos"));
        } catch (Exception e) {
            log.error("Login error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.failure("Error al iniciar sesión"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest registerRequest,
            HttpServletRequest request) {
        try {
            // Check if username already exists
            if (!userService.isUsernameAvailable(registerRequest.getUsername())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(AuthResponse.failure("El nombre de usuario ya está en uso"));
            }

            if (!userService.isEmailAvailable(registerRequest.getEmail())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(AuthResponse.failure("El email ya está registrado"));
            }

            // Create new user
            User user = new User();
            user.setUsername(registerRequest.getUsername());
            user.setEmail(registerRequest.getEmail());
            user.setPassword(registerRequest.getPassword());
            
            User savedUser = userService.register(user);

            // Auto-login after registration
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            registerRequest.getUsername(),
                            registerRequest.getPassword()
                    )
            );

            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);

            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
            session.setMaxInactiveInterval(86400); // 24 hours

            log.info("User {} registered with role {}", savedUser.getUsername(), savedUser.getRole());
            return ResponseEntity.ok(AuthResponse.success(savedUser));
        } catch (Exception e) {
            log.error("Registration error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.failure("Error al registrar usuario"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            SecurityContextHolder.clearContext();
            return ResponseEntity.ok(AuthResponse.success(null));
        } catch (Exception e) {
            return ResponseEntity.ok(AuthResponse.success(null));
        }
    }

    @GetMapping("/check-username")
    public ResponseEntity<AvailabilityResponse> checkUsername(@RequestParam String username) {
        return ResponseEntity.ok(new AvailabilityResponse(userService.isUsernameAvailable(username)));
    }

    @GetMapping("/check-email")
    public ResponseEntity<AvailabilityResponse> checkEmail(@RequestParam String email) {
        return ResponseEntity.ok(new AvailabilityResponse(userService.isEmailAvailable(email)));
    }

    @GetMapping("/status")
    public ResponseEntity<AuthResponse> status() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated() ||
                    "anonymousUser".equals(authentication.getPrincipal())) {
                return ResponseEntity.ok(AuthResponse.unauthenticated());
            }
            
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                    .orElse(null);
            
            if (user == null) {
                return ResponseEntity.ok(AuthResponse.unauthenticated());
            }
            
            return ResponseEntity.ok(AuthResponse.success(user));
        } catch (Exception e) {
            return ResponseEntity.ok(AuthResponse.unauthenticated());
        }
    }
}
