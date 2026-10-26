package com.threatlens.backend.search;

import com.threatlens.backend.domain.AlertEntity;
import com.threatlens.backend.domain.SecurityEventEntity;
import com.threatlens.backend.repository.AlertRepository;
import com.threatlens.backend.repository.EventRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/search")
public class SearchController {

    private final EventSearchIndex index;
    private final EventRepository events;
    private final AlertRepository alerts;

    public SearchController(EventSearchIndex index, EventRepository events, AlertRepository alerts) {
        this.index = index;
        this.events = events;
        this.alerts = alerts;
    }

    /** Analyst or admin. Every filter is optional. Example: ?sourceIp=198.51.100.169&severity=HIGH */
    @GetMapping("/events")
    public Map<String, Object> search(
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        EventSearchIndex.Page result = index.search(
                new EventSearchIndex.Criteria(sourceIp, eventType, severity, from, to), safePage, safeSize);
        return Map.of("total", result.total(), "page", safePage, "size", safeSize, "items", result.items());
    }

    /** Admin only. Rebuilds the search index from Postgres, then re-applies alert severities. */
    @PostMapping("/reindex")
    public Map<String, Object> reindex() {
        long indexed = 0;
        Page<SecurityEventEntity> page;
        int number = 0;
        do {
            page = events.findAll(PageRequest.of(number++, 500));
            index.indexEvents(page.getContent());
            indexed += page.getNumberOfElements();
        } while (page.hasNext());

        for (AlertEntity alert : alerts.findAll()) {
            index.applySeverity(alert.getEvidenceEventIds(), alert.getBand());
        }
        return Map.of("indexedEvents", indexed, "alertsApplied", alerts.count());
    }
}