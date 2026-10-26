package com.threatlens.backend.service;

import com.threatlens.backend.domain.AppUser;
import com.threatlens.backend.dto.Api.LoginRequest;
import com.threatlens.backend.dto.Api.LoginResponse;
import com.threatlens.backend.error.InvalidCredentialsException;
import com.threatlens.backend.error.TooManyAttemptsException;
import com.threatlens.backend.ratelimit.LoginRateLimiter;
import com.threatlens.backend.repository.UserRepository;
import com.threatlens.backend.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;
    private final LoginRateLimiter limiter;

    public AuthService(UserRepository users, PasswordEncoder encoder, JwtService jwtService,
                       LoginRateLimiter limiter) {
        this.users = users;
        this.encoder = encoder;
        this.jwtService = jwtService;
        this.limiter = limiter;
    }

    /**
     * Checks the rate limit, then the password. The same error is used for "no such user"
     * and "wrong password", so attackers cannot learn which usernames exist.
     */
    public LoginResponse login(LoginRequest request) {
        if (!limiter.allow(request.username())) {
            throw new TooManyAttemptsException();
        }
        AppUser user = users.findByUsername(request.username())
                .orElseThrow(InvalidCredentialsException::new);
        if (!encoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
        String token = jwtService.issue(user.getUsername(), user.getRole());
        return new LoginResponse(token, user.getUsername(), user.getRole().name(),
                jwtService.expiresInSeconds());
    }
}