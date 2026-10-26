package com.threatlens.backend.search;

import com.threatlens.backend.domain.SecurityEventEntity;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/** Search over events. Postgres stays the source of truth; this index is a copy for fast search. */
public interface EventSearchIndex {

    void indexEvents(List<SecurityEventEntity> events);

    /** Sets each event's severity to the highest band of any alert that cites it. */
    void applySeverity(Collection<String> eventIds, String band);

    Page search(Criteria criteria, int page, int size);

    /** Filters. Any field left null is ignored. severity means "at least this severe". */
    record Criteria(String sourceIp, String eventType, String severity, Instant from, Instant to) {
    }

    record Page(long total, List<Map<String, Object>> items) {
    }
}