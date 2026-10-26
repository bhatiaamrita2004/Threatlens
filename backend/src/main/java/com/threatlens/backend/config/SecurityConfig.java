package com.threatlens.backend.config;

import com.threatlens.backend.security.JwtAuthFilter;
import com.threatlens.backend.security.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Who may call what:
 * - login and API docs: anyone
 * - read endpoints (GET): ANALYST or ADMIN
 * - feedback on an alert: ANALYST or ADMIN
 * - ingesting events, alerts and incidents (POST): ADMIN only
 * - search reindex (POST): ADMIN only
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService) throws Exception {
        http
                .csrf(csrf -> csrf.disable())                       // token-based API, no cookies
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/v3/api-docs/**",
                 "/swagger-ui/**", "/swagger-ui.html","/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/events", "/api/alerts", "/api/incidents")
                        .hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/alerts/*/feedback")
                        .hasAnyRole("ANALYST", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/search/reindex")
                        .hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/**")
                        .hasAnyRole("ANALYST", "ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(e -> e.authenticationEntryPoint(
                        (request, response, ex) -> response.setStatus(HttpServletResponse.SC_UNAUTHORIZED)))
                .addFilterBefore(new JwtAuthFilter(jwtService), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}