package com.alberto.tfm.vulnerabilidades.controller;

import com.alberto.tfm.vulnerabilidades.dto.AvailabilityResponse;
import com.alberto.tfm.vulnerabilidades.dto.UpdateProfileRequest;
import com.alberto.tfm.vulnerabilidades.models.User;
import com.alberto.tfm.vulnerabilidades.repository.UserRepository;
import com.alberto.tfm.vulnerabilidades.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserRepository userRepository;
    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<User> getProfile(Authentication authentication) {
        return userRepository.findByUsername(authentication.getName())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/check-email")
    public ResponseEntity<AvailabilityResponse> checkEmail(
            @RequestParam String email,
            Authentication authentication) {
        boolean available = userService.isEmailAvailableForUser(authentication.getName(), email);
        return ResponseEntity.ok(new AvailabilityResponse(available));
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            Authentication authentication) {
        try {
            User updatedUser = userService.updateProfile(
                    authentication.getName(),
                    request.getEmail(),
                    request.getCurrentPassword(),
                    request.getNewPassword());
            log.info("Updated profile for user {}", authentication.getName());
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            log.warn("Profile update failed for {}: {}", authentication.getName(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.error("Error updating profile: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(Map.of("message", "Error al actualizar el perfil"));
        }
    }

    @PutMapping("/darkmode")
    public ResponseEntity<User> updateDarkmode(
            @RequestBody Map<String, Boolean> body,
            Authentication authentication) {
        try {
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

            Boolean darkmode = body.get("darkmode");
            if (darkmode != null) {
                user.setDarkmode(darkmode);
                User updatedUser = userRepository.save(user);
                log.info("Updated darkmode to {} for user {}", darkmode, username);
                return ResponseEntity.ok(updatedUser);
            }

            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Error updating darkmode: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}
