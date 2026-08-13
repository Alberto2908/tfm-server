package com.alberto.tfm.vulnerabilidades.config;

import com.alberto.tfm.vulnerabilidades.service.impl.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
            )
            .authorizeHttpRequests(auth -> auth
                // Auth endpoints - public
                .requestMatchers("/api/auth/**").permitAll()

                // Health check (keep-alive de Render y monitorización) - public
                .requestMatchers(HttpMethod.GET, "/health").permitAll()
                
                // User endpoints - authenticated
                .requestMatchers("/api/user/**").authenticated()

                // Dashboard - visible para cualquier usuario logueado
                .requestMatchers(HttpMethod.GET, "/api/dashboard/**").authenticated()

                // Vulnerabilities - GET public, write needs auth
                .requestMatchers(HttpMethod.GET, "/api/vulnerability/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/vulnerability/**").authenticated()
                .requestMatchers(HttpMethod.PUT, "/api/vulnerability/**").authenticated()
                .requestMatchers(HttpMethod.DELETE, "/api/vulnerability/**").authenticated()
                
                // Verify endpoint - admin only
                .requestMatchers(HttpMethod.PUT, "/api/vulnerability/*/verify").hasRole("ADMIN")

                // Agentes de IA - solo admin puede disparar los ciclos manualmente
                .requestMatchers(HttpMethod.POST, "/api/agent/**").hasRole("ADMIN")

                // Comprobación manual de nuevas vulnerabilidades en NVD - solo admin
                .requestMatchers(HttpMethod.POST, "/api/nvd/**").hasRole("ADMIN")

                .anyRequest().permitAll()
            )
            .exceptionHandling(ex -> ex.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .authenticationProvider(authenticationProvider());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:4200",
            "http://127.0.0.1:4200",
            "https://vulnradar-tfm.vercel.app"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        // El navegador necesita leer Content-Disposition para nombrar las descargas
        configuration.setExposedHeaders(Arrays.asList("Content-Disposition"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
