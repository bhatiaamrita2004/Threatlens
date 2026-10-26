package com.threatlens.backend.service;

import com.threatlens.backend.domain.AppUser;
import com.threatlens.backend.dto.Api.LoginRequest;
import com.threatlens.backend.error.InvalidCredentialsException;
import com.threatlens.backend.error.TooManyAttemptsException;
import com.threatlens.backend.ratelimit.LoginRateLimiter;
import com.threatlens.backend.repository.UserRepository;
import com.threatlens.backend.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for the login rules. Every collaborator is mocked. */
class AuthServiceTest {

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final JwtService jwt = mock(JwtService.class);
    private final LoginRateLimiter limiter = mock(LoginRateLimiter.class);
    private final AuthService auth = new AuthService(users, encoder, jwt, limiter);

    @Test
    void rateLimitedAttemptIsRefusedBeforeAnyPasswordCheck() {
        when(limiter.allow("nobody")).thenReturn(false);

        assertThatThrownBy(() -> auth.login(new LoginRequest("nobody", "whatever")))
                .isInstanceOf(TooManyAttemptsException.class);
        verifyNoInteractions(users, encoder);
    }

    @Test
    void unknownUserGetsTheSameErrorAsAWrongPassword() {
        when(limiter.allow("nobody")).thenReturn(true);
        when(users.findByUsername("nobody")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> auth.login(new LoginRequest("nobody", "x")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void wrongPasswordIsRejectedWithoutIssuingAToken() {
        AppUser user = mock(AppUser.class);
        when(limiter.allow("analyst")).thenReturn(true);
        when(users.findByUsername("analyst")).thenReturn(Optional.of(user));
        when(user.getPasswordHash()).thenReturn("hash");
        when(encoder.matches("bad", "hash")).thenReturn(false);

        assertThatThrownBy(() -> auth.login(new LoginRequest("analyst", "bad")))
                .isInstanceOf(InvalidCredentialsException.class);
        verifyNoInteractions(jwt);
    }
}