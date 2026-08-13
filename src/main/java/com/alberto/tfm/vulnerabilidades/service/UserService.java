package com.alberto.tfm.vulnerabilidades.service;

import com.alberto.tfm.vulnerabilidades.models.User;
import com.alberto.tfm.vulnerabilidades.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public User register(User user) {
        String username = user.getUsername().trim();
        String email = user.getEmail().trim();

        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("El nombre de usuario ya está en uso");
        }

        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new RuntimeException("El email ya está registrado");
        }

        user.setUsername(username);
        user.setEmail(email);
        validateStrongPassword(user.getPassword());
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }

        return userRepository.save(user);
    }

    public boolean isUsernameAvailable(String username) {
        if (username == null || username.isBlank()) {
            return false;
        }
        return !userRepository.existsByUsername(username.trim());
    }

    public boolean isEmailAvailable(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        return !userRepository.existsByEmailIgnoreCase(email.trim());
    }

    public boolean isEmailAvailableForUser(String username, String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        String normalizedEmail = email.trim();
        return userRepository.findByUsername(username)
                .map(user -> user.getEmail().equalsIgnoreCase(normalizedEmail)
                        || !userRepository.existsByEmailIgnoreCase(normalizedEmail))
                .orElse(false);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public boolean validatePassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    public User update(User user) {
        return userRepository.save(user);
    }

    public User updateProfile(String username, String email, String currentPassword, String newPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        String normalizedEmail = email.trim();

        if (!user.getEmail().equalsIgnoreCase(normalizedEmail)
                && userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw new RuntimeException("El email ya está registrado");
        }

        user.setEmail(normalizedEmail);

        if (newPassword != null && !newPassword.isBlank()) {
            validateStrongPassword(newPassword);
            if (currentPassword == null || currentPassword.isBlank()) {
                throw new RuntimeException("La contraseña actual es obligatoria para cambiar la contraseña");
            }
            if (!validatePassword(currentPassword, user.getPassword())) {
                throw new RuntimeException("La contraseña actual no es correcta");
            }
            user.setPassword(passwordEncoder.encode(newPassword));
        }

        return userRepository.save(user);
    }

    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }

    private void validateStrongPassword(String password) {
        if (password == null || password.length() < 8) {
            throw new RuntimeException("La contraseña debe tener al menos 8 caracteres");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new RuntimeException("La contraseña debe incluir al menos una mayúscula");
        }
        if (!password.matches(".*[a-z].*")) {
            throw new RuntimeException("La contraseña debe incluir al menos una minúscula");
        }
        if (!password.matches(".*\\d.*")) {
            throw new RuntimeException("La contraseña debe incluir al menos un número");
        }
        if (!password.matches(".*[^A-Za-z0-9].*")) {
            throw new RuntimeException("La contraseña debe incluir al menos un carácter especial");
        }
    }
}
