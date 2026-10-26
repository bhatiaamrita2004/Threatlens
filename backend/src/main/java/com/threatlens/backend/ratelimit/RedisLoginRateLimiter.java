package com.threatlens.backend.ratelimit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Fixed-window rate limit kept in Redis. Each username gets a counter that expires after the
 * window. The first attempt starts the timer; attempts past the limit are refused.
 */
@Component
@ConditionalOnProperty(name = "threatlens.redis.enabled", havingValue = "true")
public class RedisLoginRateLimiter implements LoginRateLimiter {

    private final StringRedisTemplate redis;
    private final long maxAttempts;
    private final Duration window;

    public RedisLoginRateLimiter(StringRedisTemplate redis,
                                 @Value("${threatlens.rate-limit.login-max-attempts:5}") long maxAttempts,
                                 @Value("${threatlens.rate-limit.login-window-seconds:60}") long windowSeconds) {
        this.redis = redis;
        this.maxAttempts = maxAttempts;
        this.window = Duration.ofSeconds(windowSeconds);
    }

    @Override
    public boolean allow(String username) {
        String key = "ratelimit:login:" + username.toLowerCase();
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redis.expire(key, window);
        }
        return count == null || count <= maxAttempts;
    }
}