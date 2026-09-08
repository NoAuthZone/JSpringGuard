package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Test fixture for JSpringGuard — Spring Security misconfiguration.
 *
 * Deliberately insecure. See {@link SecureSecurityConfig} for the corrected
 * counterpart, which the scanner should leave alone.
 */
@EnableWebSecurity
public class InsecureSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // EXPECT: CSRF disabled
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                // EXPECT: sensitive path opened without authentication
                .requestMatchers("/actuator/**").permitAll()
                // EXPECT: every remaining request open
                .anyRequest().permitAll()
            )
            .headers(headers -> headers
                // EXPECT: clickjacking protection switched off
                .frameOptions(frame -> frame.disable())
            )
            // EXPECT: remember-me without a fixed key
            .rememberMe();
        return http.build();
    }

    // EXPECT: plaintext password storage
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
