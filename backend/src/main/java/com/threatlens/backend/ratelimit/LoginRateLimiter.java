package com.threatlens.backend.ratelimit;

/** Decides whether a login attempt may go ahead. */
public interface LoginRateLimiter {

    /** Counts this attempt. Returns false once the username has tried too often in the window. */
    boolean allow(String username);
}