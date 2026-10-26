package com.threatlens.backend.ratelimit;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Used when Redis is turned off (for example in tests): every attempt is allowed. */
@Component
@ConditionalOnProperty(name = "threatlens.redis.enabled", havingValue = "false")
public class NoOpLoginRateLimiter implements LoginRateLimiter {

    @Override
    public boolean allow(String username) {
        return true;
    }
}