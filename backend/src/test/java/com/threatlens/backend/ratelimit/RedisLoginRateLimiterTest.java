package com.threatlens.backend.ratelimit;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the Redis rate limiter. Redis itself is mocked, so these run without a server.
 * They check the counting rules; the real Redis behaviour is covered by the manual checks in
 * the Phase 11 notes.
 */
class RedisLoginRateLimiterTest {

    @SuppressWarnings("unchecked")
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> ops = mock(ValueOperations.class);

    private RedisLoginRateLimiter limiterWithMax(long maxAttempts) {
        when(redis.opsForValue()).thenReturn(ops);
        return new RedisLoginRateLimiter(redis, maxAttempts, 60);
    }

    @Test
    void allowsUpToTheLimitThenRefuses() {
        RedisLoginRateLimiter limiter = limiterWithMax(5);
        when(ops.increment("ratelimit:login:nobody")).thenReturn(1L, 2L, 3L, 4L, 5L, 6L);

        for (int i = 0; i < 5; i++) {
            assertThat(limiter.allow("nobody")).as("attempt %d", i + 1).isTrue();
        }
        assertThat(limiter.allow("nobody")).as("attempt 6").isFalse();
    }

    @Test
    void windowIsStartedOnlyByTheFirstAttempt() {
        RedisLoginRateLimiter limiter = limiterWithMax(5);
        when(ops.increment("ratelimit:login:nobody")).thenReturn(1L, 2L);

        limiter.allow("nobody");
        limiter.allow("nobody");

        verify(redis, times(1)).expire("ratelimit:login:nobody", Duration.ofSeconds(60));
    }

    @Test
    void usernamesAreCaseInsensitive() {
        RedisLoginRateLimiter limiter = limiterWithMax(5);
        when(ops.increment("ratelimit:login:admin")).thenReturn(1L);

        limiter.allow("ADMIN");

        verify(ops).increment("ratelimit:login:admin");
    }

    @Test
    void aMissingCounterFromRedisIsAllowed() {
        // Redis returns no value: fail open so that a Redis hiccup does not lock everyone out.
        RedisLoginRateLimiter limiter = limiterWithMax(5);
        when(ops.increment(anyString())).thenReturn(null);

        assertThat(limiter.allow("someone")).isTrue();
    }
}