package com.threatlens.backend.domain;

/** An analyst's judgement on one alert. Changes the alert's status (see AlertService). */
public enum Verdict {
    TRUE_POSITIVE,
    FALSE_POSITIVE,
    NEEDS_REVIEW
}
