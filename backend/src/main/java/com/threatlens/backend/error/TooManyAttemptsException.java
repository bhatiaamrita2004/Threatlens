package com.threatlens.backend.error;

public class TooManyAttemptsException extends RuntimeException {

    public TooManyAttemptsException() {
        super("too many login attempts, try again shortly");
    }
}