package com.alberto.tfm.vulnerabilidades.dto;

import com.alberto.tfm.vulnerabilidades.models.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private boolean authenticated;
    private String username;
    private String email;
    private String role;
    private String message;
    private User user;

    public static AuthResponse success(User user) {
        return new AuthResponse(true, user.getUsername(), user.getEmail(), user.getRole(), "Authentication successful", user);
    }

    public static AuthResponse failure(String message) {
        return new AuthResponse(false, null, null, null, message, null);
    }

    public static AuthResponse unauthenticated() {
        return new AuthResponse(false, null, null, null, "Not authenticated", null);
    }
}
